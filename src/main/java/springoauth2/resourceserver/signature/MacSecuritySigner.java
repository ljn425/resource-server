package springoauth2.resourceserver.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.security.core.userdetails.UserDetails;

public class MacSecuritySigner extends SecuritySigner {

    @Override
    public String getJwtToken(UserDetails user, JWK jwk) throws JOSEException {
        MACSigner jwsSigner = new MACSigner(((OctetSequenceKey) jwk).toSecretKey());
        return super.getJwtTokenInternal(jwsSigner, user, jwk);
    }
}
