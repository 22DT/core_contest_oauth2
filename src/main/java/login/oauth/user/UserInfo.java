package login.oauth.user;

import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import static lombok.AccessLevel.PROTECTED;

@Builder
@AllArgsConstructor(access = PROTECTED)
@Getter
public class UserInfo {
    private String email;
    private String profileUrl;
    private String nickname;
    @Enumerated(EnumType.STRING)
    private RoleType role;
}
