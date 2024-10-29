package login.oauth.global;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Getter
@Component
public class JwtTokenUtil {

    private static String secretKey;
    private static Long accessTokenExpiredTimeMs;
    private static Long refreshTokenExpiredTimeMs;
    public static String TOKEN_TYPE="token_type";

    public static String ACCESS_TOKEN="access_token";
    public static String REFRESH_TOKEN="refresh_token";
    public static String USER_ID="user_id";
    public static String IS_GUEST="is_guest";


    public static String generateAccessToken(Long userId) {
        Claims claims = Jwts.claims();
        claims.put(TOKEN_TYPE, ACCESS_TOKEN);
        claims.put(USER_ID, userId);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiredTimeMs))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public static String generateRefreshToken(Long userId) {
        Claims claims = Jwts.claims();
        claims.put(TOKEN_TYPE, REFRESH_TOKEN);
        claims.put(USER_ID, userId);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiredTimeMs))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }





    public static String getTokenType(String token){
        return extractAllClaims(token).get(TOKEN_TYPE, String.class);
    }
    public static String getTokenType(Claims claims){
        return claims.get(TOKEN_TYPE, String.class);
    }

    public static Boolean isTokenExpired(String token) {
        Date expiration = extractAllClaims(token).getExpiration();
        return expiration.before(new Date());
    }

    public static Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private static Key getSigningKey() {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }


    @Value("${jwt.token.secret-key}")
    public void setSecretKey(String secretKey) {
        JwtTokenUtil.secretKey = secretKey;
    }

    @Value("${jwt.access-token.expired-time-ms}")
    public  void setAccessTokenExpiredTimeMs(Long accessTokenExpiredTimeMs) {
        JwtTokenUtil.accessTokenExpiredTimeMs = accessTokenExpiredTimeMs;
    }

    @Value("${jwt.refresh-token.expired-time-ms}")
    public  void setRefreshTokenExpiredTimeMs(Long refreshTokenExpiredTimeMs) {
        JwtTokenUtil.refreshTokenExpiredTimeMs = refreshTokenExpiredTimeMs;
    }



}
