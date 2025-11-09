package com.example.demo.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 【重要】暴露 AuthenticationManager Bean
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * 配置 SecurityFilterChain
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http                // 授权请求配置
                .authorizeHttpRequests(authorize -> authorize
                        // 允许所有人访问自定义的登录接口和登出接口
                        .requestMatchers("/index.html", "/", "/api/login", "/api/logout").permitAll()
                        // 所有其他请求都需要认证
                        .anyRequest().authenticated()
                )

                // 异常处理 - 针对未认证的 AJAX 请求
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            PrintWriter writer = response.getWriter();
                            Map<String, Object> result = new HashMap<>();
                            result.put("code", HttpStatus.UNAUTHORIZED.value());
                            result.put("msg", "exception:" + authException.getMessage());
                            writer.write(objectMapper.writeValueAsString(result));
                        })
                )
                // 登出配置
                .logout(logout -> logout
                        .logoutUrl("/api/logout") // 登出 URL
                        .logoutSuccessHandler((request, response, authentication) -> { // 自定义登出成功处理器
                            response.setStatus(HttpStatus.OK.value());
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            PrintWriter writer = response.getWriter();
                            Map<String, Object> result = new HashMap<>();
                            result.put("code", HttpStatus.OK.value());
                            result.put("msg", "登出成功");
                            writer.write(objectMapper.writeValueAsString(result));
                        })
                        .permitAll()
                )
                // CSRF 配置
                .csrf(csrf -> csrf.disable()); // 为了方便测试 AJAX，继续禁用 CSRF


        http.sessionManagement(cfg->{
            cfg.maximumSessions(1).maxSessionsPreventsLogin(true);
        });



        return http.build();
    }

    // 保持不变：密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 保持不变：内存用户存储 (用于简单测试)
    @Bean
    public InMemoryUserDetailsManager userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("123456")) // 密码是 "password"
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }



    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

}
