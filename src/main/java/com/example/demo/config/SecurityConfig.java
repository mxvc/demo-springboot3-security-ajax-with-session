package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    // 配置 HTTP 安全
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(cfg->cfg.disable());

        http.authorizeHttpRequests(authz->{
            authz.requestMatchers("/api/login","/","/index.html").permitAll();
            authz.anyRequest().authenticated();
        });

        http.formLogin(form -> form.defaultSuccessUrl("/msg")
        );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user =
                User.withUsername("admin")
                        .password(passwordEncoder().encode("123456")) // 密码要加密！
                        .roles("USER")
                        .build();
        return new InMemoryUserDetailsManager(user);
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
