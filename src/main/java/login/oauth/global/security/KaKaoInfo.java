package login.oauth.global.security;

import lombok.*;

import static lombok.AccessLevel.PROTECTED;

@Getter
@Builder
@AllArgsConstructor(access = PROTECTED)
@ToString
public class KaKaoInfo {
    private String nickname;
    private String email;
    private String profileUrl;


}
