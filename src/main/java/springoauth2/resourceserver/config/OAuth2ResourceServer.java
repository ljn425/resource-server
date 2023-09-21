package springoauth2.resourceserver.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import springoauth2.resourceserver.filter.authentication.JwtAuthenticationFilter;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class OAuth2ResourceServer {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(request -> request
                    .requestMatchers("/").permitAll()
                    .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors
                        .configurationSource(corsConfigurationSource())
                )
                .userDetailsService(userDetailsService())
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*"); // CORS 허용할 Origin(도메인) 설정
        configuration.addAllowedMethod("*"); // CORS 허용할 HTTP Method 설정
        configuration.addAllowedHeader("*"); // CORS 허용할 HTTP Header 설정
//        configuration.setAllowCredentials(true); 토큰 인증 설정을 true로 하면 addAllowedOrigin() 설정에서 "*"(와일드카드) 를 사용할 수 없다. -> 예외 발생
//        configuration.setMaxAge(3600L); // pre-flight(사전 요청) 요청 결과를 캐시에 저장할 시간 설정

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource(); // CORS 허용 경로 설정
        source.registerCorsConfiguration("/**", configuration); // 모든 경로에 대해 CORS 허용
        return source;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User
                .withUsername("user")
                .password("1234")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter();
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
        return jwtAuthenticationFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }


}
