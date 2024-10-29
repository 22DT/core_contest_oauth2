package login.oauth.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface RefreshTokenJpaRepository extends JpaRepository<RefreshToken, Long> {

    @Query("select token from RefreshToken token where token.userId=:userId and token.isBlacklist is false")
    Optional<RefreshToken> findByUserIdAndBlacklistIsFalse(@Param("userId")Long userId);
    Optional<RefreshToken> findByUserIdAndRefreshToken(Long userId, String refreshToken);
}
