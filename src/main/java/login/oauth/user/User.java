package login.oauth.user;

import jakarta.persistence.*;
import lombok.*;

import static jakarta.persistence.GenerationType.IDENTITY;
import static lombok.AccessLevel.PROTECTED;

@Entity
@NoArgsConstructor(access = PROTECTED)
@Builder
@AllArgsConstructor
@Getter
@Table(name="users")
@ToString
public class User {
    @Id
    @GeneratedValue(strategy = IDENTITY)
    @Column(name = "user_id")
    private Long id;

    private String email;
    private String profileUrl;
    private String nickname;
    @Enumerated(EnumType.STRING)
    private RoleType role;
}
