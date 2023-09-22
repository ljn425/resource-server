package springoauth2.resourceserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springoauth2.resourceserver.signature.MacSecuritySigner;
import springoauth2.resourceserver.signature.RsaSecuritySigner;

@Configuration
public class SignatureConfig {


    /**
     * 대칭키 기반 서명을 위한 서명 객체
     */
    @Bean
    public MacSecuritySigner macSecuritySigner() {
        return new MacSecuritySigner();
    }

    /**
     * 대칭키 기반 서명을 위한 비밀키(시크릿키) 생성
     */
    @Bean
    public OctetSequenceKey octetSequenceKey() throws JOSEException {
        return new OctetSequenceKeyGenerator(256)
                .keyID("macKey")
                .algorithm(JWSAlgorithm.HS256)
                .generate();
    }

    /**
     * 비대칭키 기반 서명을 위한 서명 객체
     */
    @Bean
    public RsaSecuritySigner rsaSecuritySigner() {
        return new RsaSecuritySigner();
    }

    /**
     * 비대칭키 기반 서명을 위한 비밀키(시크릿키) 생성
     */
    @Bean
    public RSAKey rsaKey() throws JOSEException {
        return new RSAKeyGenerator(2048)
                .keyID("rsaKey")
                .algorithm(JWSAlgorithm.RS256)
                .generate();
    }
}
