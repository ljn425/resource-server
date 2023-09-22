package springoauth2.resourceserver.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 서명 공통 클래스
 * -자식 클래스
 * -> MacSecuritySigner : MAC 서명(대칭키)
 * -> RsaSecuritySigner : RSA 서명(비대칭키)
 */
public abstract class SecuritySigner {
    /**
     * JWT 토큰 생성 및 반환
     */
    protected String getJwtTokenInternal(MACSigner jwsSigner, UserDetails user, JWK jwk) throws JOSEException {
        // JWT 헤더
        JWSHeader header = new JWSHeader.Builder((JWSAlgorithm) jwk.getAlgorithm())
                .keyID(jwk.getKeyID())
                .build();

        // JWT 페이로드(중간 부분)
        List<String> authorities = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .issuer("http://localhost:8081") // 발급자
                .claim("username", user.getUsername()) // 사용자명
                .claim("authority", authorities) // 권한
                .expirationTime(new Date(new Date().getTime() + 1000 * 60 * 5)) // 5분
                .build();

        // JWT 서명(헤더 + 페이로드의 내용을 암호화 한 것)
        SignedJWT signedJWT = new SignedJWT(header, jwtClaimsSet);
        signedJWT.sign(jwsSigner);
        
        return signedJWT.serialize(); // 생성된 JWT 토큰을 문자열로 반환
    }

    public abstract String getJwtToken(UserDetails user, JWK jwk) throws JOSEException;
}
