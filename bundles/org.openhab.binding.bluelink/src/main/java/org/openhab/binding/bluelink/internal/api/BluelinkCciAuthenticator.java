/*
 * Copyright (c) 2010-2026 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.bluelink.internal.api;

import java.math.BigInteger;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.crypto.Cipher;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.util.StringContentProvider;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpStatus;

import com.google.gson.Gson;

/**
 * Authenticates Hyundai and Kia European accounts through the OneApp/CCI API.
 *
 * @author Didier Gonze - Initial contribution
 */
@NonNullByDefault
final class BluelinkCciAuthenticator {
    private static final String APPLICATION_JSON = "application/json";
    private static final String FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";
    private static final String CLIENT_VERSION = "1.3.3";
    private static final String MOBILE_USER_AGENT = "Mozilla/5.0 (Linux; Android 4.1.1; Galaxy Nexus Build/JRO03C) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Mobile Safari/535.19_CCS_APP_AOS";
    private static final Duration CCS_EXPIRY_FALLBACK = Duration.ofHours(1);
    private static final Duration CCS_EXPIRY_MAX_VALIDITY = Duration.ofHours(24);
    private static final int MAX_REDIRECTS = 10;

    private final HttpClient httpClient;
    private final Gson gson;
    private final String loginBaseUrl;
    private final CciConfig config;
    private final String username;
    private final String password;
    private final String language;
    private final String country;
    private final ZoneId zoneId;

    private @Nullable CciTokenBundle tokenBundle;

    BluelinkCciAuthenticator(final HttpClient httpClient, final Gson gson, final String loginBaseUrl,
            final CciConfig config, final String username, final String password, final Locale locale,
            final ZoneId zoneId) {
        this.httpClient = httpClient;
        this.gson = gson;
        this.loginBaseUrl = loginBaseUrl;
        this.config = config;
        this.username = username;
        this.password = password;
        this.zoneId = zoneId;

        this.language = locale.getLanguage().isBlank() ? "en" : locale.getLanguage();
        this.country = locale.getCountry().isBlank() ? "de" : locale.getCountry().toLowerCase(Locale.ROOT);
    }

    CcsToken authenticate() throws BluelinkApiException {
        final CciTokenBundle current = tokenBundle;
        if (current != null && !current.refreshToken.isBlank()) {
            try {
                return refresh(current);
            } catch (final BluelinkApiException e) {
                // A stale CCI session must not prevent a fresh password login.
            }
        }
        return loginWithPassword();
    }

    boolean hasSession() {
        return tokenBundle != null;
    }

    private CcsToken loginWithPassword() throws BluelinkApiException {
        final SessionCookies cookies = new SessionCookies();
        authorize(cookies);

        final CertificateResponse certificate = sendJson(
                request(loginBaseUrl + "/auth/api/v1/accounts/certs", HttpMethod.GET, cookies).header(HttpHeader.ACCEPT,
                        APPLICATION_JSON),
                CertificateResponse.class, "fetch CCI RSA certificate");
        if (certificate.retValue() == null || certificate.retValue().kid().isBlank()
                || certificate.retValue().n().isBlank() || certificate.retValue().e().isBlank()) {
            throw new BluelinkApiException("CCI RSA certificate response is incomplete");
        }

        final String encryptedPassword = encryptPassword(password, certificate.retValue().n(),
                certificate.retValue().e());
        final Map<String, String> fields = new LinkedHashMap<>();
        fields.put("client_id", config.oneAppClientId());
        fields.put("encryptedPassword", "true");
        fields.put("password", encryptedPassword);
        fields.put("redirect_uri", config.oneAppRedirectUri());
        fields.put("scope", "");
        fields.put("nonce", "");
        fields.put("state", "ccsp");
        fields.put("username", username);
        fields.put("connector_session_key", "");
        fields.put("kid", certificate.retValue().kid());
        fields.put("_csrf", "");

        final Request signin = request(loginBaseUrl + "/auth/account/signin", HttpMethod.POST, cookies)
                .content(new StringContentProvider(form(fields)), FORM_CONTENT_TYPE).followRedirects(false);
        final ContentResponse signinResponse = send(signin, "CCI sign-in");
        cookies.capture(signinResponse);
        if (signinResponse.getStatus() != HttpStatus.FOUND_302) {
            throw new BluelinkApiException("CCI sign-in failed: HTTP %d (%s)".formatted(signinResponse.getStatus(),
                    truncate(signinResponse.getContentAsString())));
        }

        final String location = signinResponse.getHeaders().get(HttpHeader.LOCATION);
        if (location == null) {
            throw new BluelinkApiException("CCI sign-in returned no redirect");
        }
        final URI redirect = URI.create(location);
        final String code = queryParameter(redirect, "code");
        if (code == null || code.isBlank()) {
            if (redirect.getPath().contains("/web/v1/user/authorization")) {
                throw new BluelinkApiException(
                        "Account consent required: log in with the manufacturer app once, accept the terms and retry");
            }
            final String description = queryParameter(redirect, "error_description");
            throw new BluelinkApiException(description != null ? "CCI sign-in rejected: " + description
                    : "Unexpected redirect after CCI sign-in: " + truncate(location));
        }

        final CciTokenBundle bundle = exchangeCciToken(UUID.randomUUID().toString(), code);
        final CcsToken token = exchangeCcsToken(bundle);
        tokenBundle = bundle;
        return token;
    }

    private void authorize(final SessionCookies cookies) throws BluelinkApiException {
        URI uri = URI.create(loginBaseUrl + "/auth/api/v2/user/oauth2/authorize?response_type=code&client_id="
                + encode(config.oneAppClientId()) + "&redirect_uri=" + encode(config.oneAppRedirectUri()) + "&lang="
                + encode(language) + "&state=ccsp&country=" + encode(country));

        for (int redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
            final ContentResponse response = send(
                    request(uri.toString(), HttpMethod.GET, cookies).followRedirects(false), "CCI authorize");
            cookies.capture(response);
            final String body = response.getContentAsString();
            final String location = response.getHeaders().get(HttpHeader.LOCATION);

            if (body.toLowerCase(Locale.ROOT).contains("abusing")
                    || (location != null && location.contains("/error?status=400"))) {
                throw new BluelinkApiException("CCI authorize rejected as an abusing request (server-side WAF block)");
            }
            if (response.getStatus() >= 200 && response.getStatus() < 300) {
                return;
            }
            if (response.getStatus() < 300 || response.getStatus() >= 400 || location == null) {
                throw new BluelinkApiException(
                        "CCI authorize failed: HTTP %d (%s)".formatted(response.getStatus(), truncate(body)));
            }
            uri = uri.resolve(location);
        }
        throw new BluelinkApiException("CCI authorize exceeded the redirect limit");
    }

    private CciTokenBundle exchangeCciToken(final String deviceId, final String code) throws BluelinkApiException {
        final Request request = cciRequest(config.apiUrl() + "/domain/api/v1/auth/token?code=" + encode(code),
                HttpMethod.POST, deviceId, "", "", "");
        final CciTokenResponse response = sendJson(request, CciTokenResponse.class, "CCI token exchange");
        final CciTokenBundle bundle = new CciTokenBundle(deviceId);
        bundle.apply(response);
        return bundle;
    }

    private CcsToken refresh(final CciTokenBundle bundle) throws BluelinkApiException {
        final Map<String, String> body = Map.of("accessToken", bundle.cciAccessToken, "refreshToken",
                bundle.refreshToken, "exchangeableAccessToken", bundle.exchangeableToken, "exchangeableRefreshToken",
                bundle.exchangeableRefreshToken, "nonCcsToken", bundle.nonCcsToken, "nonCcsRefreshToken",
                bundle.nonCcsRefreshToken, "idToken", bundle.idToken);
        final Request request = cciRequest(config.apiUrl() + "/domain/api/v2/auth/token-refresh", HttpMethod.POST,
                bundle.deviceId, bundle.cciAccessToken, bundle.nonCcsToken, bundle.exchangeableToken)
                .content(new StringContentProvider(gson.toJson(body)), APPLICATION_JSON);
        bundle.apply(sendJson(request, CciTokenResponse.class, "CCI token refresh"));
        return exchangeCcsToken(bundle);
    }

    private CcsToken exchangeCcsToken(final CciTokenBundle bundle) throws BluelinkApiException {
        final Request request = cciRequest(config.apiUrl() + "/domain/api/v1/auth/token-exchange?serviceType=CCS",
                HttpMethod.POST, bundle.deviceId, bundle.cciAccessToken, bundle.nonCcsToken, bundle.exchangeableToken);
        final CcsTokenResponse response = sendJson(request, CcsTokenResponse.class, "CCS token exchange");
        if (response.accessToken() == null || response.accessToken().isBlank()) {
            throw new BluelinkApiException("CCS token exchange returned no access token");
        }
        return new CcsToken(response.accessToken(), parseExpiry(response.expiresTime()));
    }

    private Request cciRequest(final String uri, final HttpMethod method, final String deviceId,
            final String cciAccessToken, final String nonCcsToken, final String exchangeableToken) {
        final Request request = httpClient.newRequest(uri).method(method)
                .timeout(AbstractBluelinkApi.HTTP_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .header("client-id", config.packageId()).header("client-name", config.clientName())
                .header("client-version", CLIENT_VERSION).header("client-os-code", "ios")
                .header("client-os-version", config.osVersion()).header("client-device-id", deviceId)
                .header("client-device-model", "iPhone")
                .header("client-notification-provider-type", config.notificationProvider())
                .header("locale", language.toUpperCase(Locale.ROOT)).header("timezone", timeZoneOffset())
                .header(HttpHeader.ACCEPT, APPLICATION_JSON).header(HttpHeader.ACCEPT_LANGUAGE, language)
                .header(HttpHeader.USER_AGENT, MOBILE_USER_AGENT);
        if (!nonCcsToken.isBlank()) {
            request.header("Authentication", nonCcsToken);
        }
        if (!cciAccessToken.isBlank()) {
            request.header(HttpHeader.AUTHORIZATION, "Bearer " + stripBearer(cciAccessToken));
        }
        if (!exchangeableToken.isBlank()) {
            request.header("exchangeable-token", exchangeableToken).header("non-ccs-token", nonCcsToken);
        }
        return request;
    }

    private Request request(final String uri, final HttpMethod method, final SessionCookies cookies) {
        final Request request = httpClient.newRequest(uri).method(method)
                .timeout(AbstractBluelinkApi.HTTP_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .header(HttpHeader.USER_AGENT, MOBILE_USER_AGENT);
        final String cookieHeader = cookies.asHeader();
        if (!cookieHeader.isBlank()) {
            request.header(HttpHeader.COOKIE, cookieHeader);
        }
        return request;
    }

    private <T> T sendJson(final Request request, final Class<T> type, final String operation)
            throws BluelinkApiException {
        final ContentResponse response = send(request, operation);
        if (response.getStatus() != HttpStatus.OK_200) {
            throw new BluelinkApiException("%s failed: HTTP %d (%s)".formatted(operation, response.getStatus(),
                    truncate(response.getContentAsString())));
        }
        final @Nullable T result = gson.fromJson(response.getContentAsString(), type);
        if (result == null) {
            throw new BluelinkApiException(operation + " returned an empty response");
        }
        return result;
    }

    private ContentResponse send(final Request request, final String operation) throws BluelinkApiException {
        try {
            return request.send();
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new BluelinkApiException(operation + " interrupted", e);
        } catch (TimeoutException | ExecutionException e) {
            throw new BluelinkApiException(operation + " failed", e);
        }
    }

    private String timeZoneOffset() {
        final int seconds = zoneId.getRules().getOffset(Instant.now()).getTotalSeconds();
        final int absoluteMinutes = Math.abs(seconds / 60);
        return "%s%02d:%02d".formatted(seconds < 0 ? "-" : "+", absoluteMinutes / 60, absoluteMinutes % 60);
    }

    static Instant parseExpiry(final long expiresTime) {
        final Instant now = Instant.now();
        final Instant candidate = Instant.ofEpochSecond(expiresTime);
        if (candidate.isAfter(now) && candidate.isBefore(now.plus(CCS_EXPIRY_MAX_VALIDITY))) {
            return candidate;
        }
        return now.plus(CCS_EXPIRY_FALLBACK);
    }

    static String encryptPassword(final String password, final String modulus, final String exponent)
            throws BluelinkApiException {
        try {
            final byte[] modulusBytes = Base64.getUrlDecoder().decode(modulus.replaceAll("=+$", ""));
            final byte[] exponentBytes = Base64.getUrlDecoder().decode(exponent.replaceAll("=+$", ""));
            final PublicKey key = KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(new BigInteger(1, modulusBytes), new BigInteger(1, exponentBytes)));
            final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return HexFormat.of().formatHex(cipher.doFinal(password.getBytes(StandardCharsets.UTF_8)));
        } catch (final GeneralSecurityException | IllegalArgumentException e) {
            throw new BluelinkApiException("Could not encrypt password for CCI authentication", e);
        }
    }

    private static String form(final Map<String, String> values) {
        return values.entrySet().stream().map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .collect(java.util.stream.Collectors.joining("&"));
    }

    private static String encode(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static @Nullable String queryParameter(final URI uri, final String name) {
        final String query = uri.getRawQuery();
        if (query == null) {
            return null;
        }
        for (final String field : query.split("&")) {
            final String[] parts = field.split("=", 2);
            if (parts.length == 2 && name.equals(java.net.URLDecoder.decode(parts[0], StandardCharsets.UTF_8))) {
                return java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static String stripBearer(final String token) {
        final String trimmed = token.trim();
        return trimmed.regionMatches(true, 0, "Bearer ", 0, 7) ? trimmed.substring(7) : trimmed;
    }

    private static String truncate(final String value) {
        return value.length() <= 300 ? value : value.substring(0, 300) + "...";
    }

    record CciConfig(String oneAppClientId, String oneAppRedirectUri, String apiUrl, String packageId,
            String clientName, String osVersion, String notificationProvider) {
        CciConfig withApiUrl(final String apiUrl) {
            return new CciConfig(oneAppClientId, oneAppRedirectUri, apiUrl, packageId, clientName, osVersion,
                    notificationProvider);
        }
    }

    record CcsToken(String accessToken, Instant expiry) {
    }

    private record CertificateResponse(@Nullable Certificate retValue) {
    }

    private record Certificate(String kid, String n, String e) {
    }

    private record CciTokenResponse(@Nullable String accessToken, @Nullable String refreshToken,
            @Nullable String nonCcsToken, @Nullable String exchangeableAccessToken,
            @Nullable String exchangeableRefreshToken, @Nullable String nonCcsRefreshToken, @Nullable String idToken) {
    }

    private record CcsTokenResponse(@Nullable String accessToken, long expiresTime) {
    }

    private static final class CciTokenBundle {
        private final String deviceId;
        private String cciAccessToken = "";
        private String refreshToken = "";
        private String nonCcsToken = "";
        private String exchangeableToken = "";
        private String exchangeableRefreshToken = "";
        private String nonCcsRefreshToken = "";
        private String idToken = "";

        private CciTokenBundle(final String deviceId) {
            this.deviceId = deviceId;
        }

        private void apply(final CciTokenResponse response) {
            cciAccessToken = nonEmpty(response.accessToken(), cciAccessToken);
            refreshToken = nonEmpty(response.refreshToken(), refreshToken);
            nonCcsToken = nonEmpty(response.nonCcsToken(), nonCcsToken);
            exchangeableToken = nonEmpty(response.exchangeableAccessToken(), exchangeableToken);
            exchangeableRefreshToken = nonEmpty(response.exchangeableRefreshToken(), exchangeableRefreshToken);
            nonCcsRefreshToken = nonEmpty(response.nonCcsRefreshToken(), nonCcsRefreshToken);
            idToken = nonEmpty(response.idToken(), idToken);
        }

        private static String nonEmpty(final @Nullable String replacement, final String current) {
            return replacement == null || replacement.isBlank() ? current : replacement;
        }
    }

    private static final class SessionCookies {
        private final Map<String, HttpCookie> cookies = new LinkedHashMap<>();

        private void capture(final ContentResponse response) {
            for (final String header : response.getHeaders().getValuesList(HttpHeader.SET_COOKIE)) {
                try {
                    for (final HttpCookie cookie : HttpCookie.parse(header)) {
                        if (cookie.getMaxAge() == 0) {
                            cookies.remove(cookie.getName());
                        } else {
                            cookies.put(cookie.getName(), cookie);
                        }
                    }
                } catch (final IllegalArgumentException e) {
                    // Ignore a malformed optional cookie instead of failing the authentication session.
                }
            }
        }

        private String asHeader() {
            return cookies.values().stream().filter(cookie -> !cookie.hasExpired())
                    .map(cookie -> cookie.getName() + "=" + cookie.getValue())
                    .collect(java.util.stream.Collectors.joining("; "));
        }
    }
}
