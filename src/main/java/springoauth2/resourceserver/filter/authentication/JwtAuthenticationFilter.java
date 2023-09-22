package springoauth2.resourceserver.filter.authentication;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.jwk.JWK;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import springoauth2.resourceserver.dto.LoginDto;
import springoauth2.resourceserver.signature.SecuritySigner;

import java.io.IOException;

/**
 * JwtAuthenticationFilter
 * 1. 송신자가 보내온 유저 정보를 받아서 인증을 처리하는 필터(송신자가 /login 유저정보를 담아 요청시 작동)
 * 2. 인증이 성공하면 JWT 토큰을 생성해서 응답헤더에 추가
 */
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private SecuritySigner securitySigner;
    private JWK jwk;

    public JwtAuthenticationFilter(SecuritySigner securitySigner, JWK jwk) {
        this.securitySigner = securitySigner;
        this.jwk = jwk;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        ObjectMapper objectMapper = new ObjectMapper();
        LoginDto loginDto = null;

        try {
            loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        return getAuthenticationManager().authenticate(authenticationToken);
    }

    /**
     * 인증이 성공했을 때 호출되는 메소드
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal();
        String jwtToken;

        try {
            jwtToken = securitySigner.getJwtToken(user, jwk);   // JWT 토큰 생성
            response.addHeader("Authorization", "Bearer " + jwtToken); // 응답헤더에 JWT 토큰 추가
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }


    }
}
