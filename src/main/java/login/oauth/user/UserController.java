package login.oauth.user;

import login.oauth.token.RefreshToken;
import login.oauth.token.RefreshTokenJpaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
@Slf4j
@Transactional // 임시
public class UserController {
    private final RefreshTokenJpaRepository refreshTokenJpaRepository;

    @GetMapping("/permit-all")
    public ResponseEntity<String> test(){
        return ResponseEntity.ok("모두 허용");
    }


    @GetMapping("/auth-required")
    public ResponseEntity<String> test3(@AuthenticationPrincipal User user){
        log.info("[TestController][test3]");
        log.info("authentication= {}", user);

        return ResponseEntity.ok("인증이 되었습니다.");
    }


    @PostMapping("/logout")
    public ResponseEntity<String> logout(@AuthenticationPrincipal User user){
        log.info("user.getId()= {}", user.getId());

        // refreshToken 블랙리스트로 바꿈. 끝?
        Optional<RefreshToken> findToken = refreshTokenJpaRepository.findByUserIdAndBlacklistIsFalse(user.getId());
        RefreshToken refreshToken = findToken.get();
        refreshToken.blacklist();

        return ResponseEntity.ok().body("로그아웃 완료");
    }
}
