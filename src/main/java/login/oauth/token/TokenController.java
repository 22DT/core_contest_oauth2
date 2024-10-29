package login.oauth.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import login.oauth.global.JwtTokenUtil;
import login.oauth.user.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static login.oauth.global.JwtTokenUtil.USER_ID;

@RestController
@RequiredArgsConstructor
@Slf4j
@Transactional
public class TokenController {
    private final RefreshTokenJpaRepository refreshTokenJpaRepository;

    /**
     *
     * @param refreshToken
     * @return
     *
     * @apiNote
     *
     * 근데 이거 refresh token 만 넘기면 되는 거야?
     * access token 같이 넘겨서 만료된 거 맞는지 확인해야 하나?
     */

    @PostMapping("/api/token-reissue")
    public ResponseEntity<Map> reissueToken(@CookieValue(name="refreshToken")String refreshToken){
        log.info("[TokenController][reissueToken]");
        // 임시로 map 이요하자
        Map<String, String> jsonResponse = new ConcurrentHashMap<>();
        try{
            log.info("refreshToken= {}", refreshToken);
            Claims claims = JwtTokenUtil.extractAllClaims(refreshToken);

            String tokenType = JwtTokenUtil.getTokenType(claims);

            // 뭔가 있지만 refreshToken 아님.
            if(!Objects.equals(tokenType, JwtTokenUtil.REFRESH_TOKEN)){
                log.warn("token is not access token");
                jsonResponse.put("msg", "token is not access token.");

                return ResponseEntity.ok(jsonResponse);

            }


            log.info("토큰이 정상입니다.");

            Long  userId = claims.get(USER_ID, Long.class);

           RefreshToken findToken = refreshTokenJpaRepository.findByUserIdAndRefreshToken(userId, refreshToken).get();

            String generatedAccessToken = JwtTokenUtil.generateAccessToken(userId);
            String generatedRefreshToken = JwtTokenUtil.generateRefreshToken(userId);

            findToken.updateRefreshToken(generatedRefreshToken);

            refreshTokenJpaRepository.save(findToken);

            jsonResponse.put(JwtTokenUtil.ACCESS_TOKEN, generatedAccessToken);
            jsonResponse.put(JwtTokenUtil.REFRESH_TOKEN, generatedRefreshToken);


        }catch (SignatureException e){
            // 서명 이상함
            log.info("서명 이상함.");
            jsonResponse.put("msg", "Invalid JWT signature. Please login again.");
        }catch(ExpiredJwtException e){
            // 토큰 만료기간 지남.
            log.info("Token is expired");
            jsonResponse.put("msg", "Token has expired. Please login again.");


        }catch (MalformedJwtException e){
            // 토큰 형식 이상함
            log.info("Malformed JWT.");
            jsonResponse.put("msg", "Malformed JWT token. Please login again.");

        }

        return ResponseEntity.ok(jsonResponse);
    }


}
