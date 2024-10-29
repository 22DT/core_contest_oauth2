package login.oauth.global.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import login.oauth.global.JwtTokenUtil;
import login.oauth.token.RefreshToken;
import login.oauth.token.RefreshTokenJpaRepository;
import login.oauth.user.RoleType;
import login.oauth.user.User;
import login.oauth.user.UserJpaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
@Slf4j
@Transactional
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final UserJpaRepository userJpaRepository;
    private final RefreshTokenJpaRepository refreshTokenJpaRepository;
    private final ObjectMapper objectMapper;


    /**
     *
     * @param request
     * @param response
     * @param authentication
     * @throws IOException
     *
     * @apiNote
     *
     */

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        log.info("[CustomAuthenticationSuccessHandler][onAuthenticationSuccess]");

        OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
        KaKaoInfo kaKaoInfo = getKaKaoInfoFrom(oAuth2User);
        Optional<User> user=userJpaRepository.findByEmail(kaKaoInfo.getEmail());
        Map<String, String> jsonResponse = new ConcurrentHashMap<>();

        log.info("KaKaoInfo= {}", kaKaoInfo);

        if(user.isPresent()){
            log.info("기존 유저");
            // ===
            String accessToken = JwtTokenUtil.generateAccessToken(user.get().getId());
            String refreshToken = JwtTokenUtil.generateRefreshToken(user.get().getId());
            // ===
            log.info("accessToken: " + accessToken);
            log.info("refreshToken: " + refreshToken);


            Optional<RefreshToken> findToken = refreshTokenJpaRepository.findByUserIdAndBlacklistIsFalse(user.get().getId());
            RefreshToken token;
            if(findToken.isEmpty()){
                log.info("refreshToken 없음");
                token=RefreshToken.builder()
                        .refreshToken(refreshToken)
                        .userId(user.get().getId())
                        .isBlacklist(false)
                        .build();

                refreshTokenJpaRepository.save(token);

            }
            else{
                log.info("refreshToken 있음");
                token=findToken.get();
                token.updateRefreshToken(refreshToken);
            }

            jsonResponse.put(JwtTokenUtil.ACCESS_TOKEN, accessToken);
            jsonResponse.put(JwtTokenUtil.REFRESH_TOKEN, refreshToken);
            jsonResponse.put("RoleType", RoleType.USER.toString());

        }
        else{
            log.info("신규 유저");

            jsonResponse.put("nickname", kaKaoInfo.getNickname());
            jsonResponse.put("email", kaKaoInfo.getEmail());
            jsonResponse.put("profileUrl", kaKaoInfo.getProfileUrl());
            jsonResponse.put("RoleType", RoleType.GUEST.toString());
        }



        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write(objectMapper.writeValueAsString(jsonResponse));
    }

    private KaKaoInfo getKaKaoInfoFrom(OAuth2User oAuth2User){
        Map<String, String> properties =  oAuth2User.getAttribute("properties");
        Map<String, Object> kakaoAccount = oAuth2User.getAttribute("kakao_account");
        String email= (String) kakaoAccount.get("email");
        String nickname = properties.get("nickname");
        String profileUrl = properties.get("profile_image");

        return KaKaoInfo.builder()
                .email(email)
                .profileUrl(profileUrl)
                .nickname(nickname)
                .build();
    }


}
