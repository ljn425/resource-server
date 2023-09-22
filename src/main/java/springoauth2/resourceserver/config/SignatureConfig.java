package springoauth2.resourceserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springoauth2.resourceserver.signature.MacSecuritySigner;

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
}
