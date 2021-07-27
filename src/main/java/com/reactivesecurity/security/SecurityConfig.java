package com.reactivesecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.chrono.ChronoLocalDate;
import java.util.function.Function;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http){
//        return http.authorizeExchange()
//                .pathMatchers(HttpMethod.GET, "/hi")
//                .authenticated()
//                .anyExchange()
//                .permitAll()
//                .and().httpBasic()
//                .and().build();

        return http.authorizeExchange()
                .anyExchange()
                .access(this::getAuthorizationDecision)
                .and().httpBasic()
                .and().formLogin()
                .and().build();
    }

    private String getRequestPath(AuthorizationContext c){
        return c.getExchange()
                .getRequest()
                .getPath()
                .toString();
    }

    private Function<Authentication, Boolean> isAdmin(){
        return p -> p.getAuthorities()
                .stream()
                .anyMatch(e -> e.getAuthority().equals("ROLE_ADMIN"));
    }

    @Bean
    public ReactiveUserDetailsService userDetailsService(){
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder.encode("user"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder.encode("admin"))
                .roles("ADMIN")
                .build();
        return new MapReactiveUserDetailsService(user, admin);
    }

    private Mono<AuthorizationDecision> getAuthorizationDecision(Mono<Authentication> authentication,
                                                                 AuthorizationContext context){
        String path = getRequestPath(context);
        boolean restrictedTime = LocalTime.now().isBefore(LocalTime.NOON);

        if(path.equals("/hi")){
            return authentication.map(isAdmin())
                    .map(auth -> auth && !restrictedTime)
                    .map(AuthorizationDecision::new);
        }else if(path.equals("/ei")){
            return Mono.just(new AuthorizationDecision(true));
        }
        return Mono.just(new AuthorizationDecision(false));
    }
}
