package login.oauth.token;

import jakarta.persistence.*;
import login.oauth.user.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import static jakarta.persistence.GenerationType.IDENTITY;
import static lombok.AccessLevel.PROTECTED;


/**
 * 회원 탈퇴 시 토큰 폐기해야 함?
 */
@Entity
@NoArgsConstructor(access = PROTECTED)
@Getter
@Builder
@AllArgsConstructor(access = PROTECTED)
public class RefreshToken {
    @Id @GeneratedValue(strategy= IDENTITY)
    @Column(name="refresh_token_id")
    private Long id;

    private Long userId;

    private String refreshToken;

    boolean isBlacklist;

    public void updateRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void blacklist(){
        isBlacklist = true;
    }
}
