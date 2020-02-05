package com.example.demo.config;

import com.example.demo.service.UserService;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

import javax.annotation.Resource;

@Configuration
@EnableAuthorizationServer
public class OAuth2ServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Resource
    private AuthenticationManager authenticationManager;

    @Resource
    private BCryptPasswordEncoder passwordEncoder;

    @Resource
    private UserService userService;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer authorizationServerEndpointsConfigurer) throws Exception {
        authorizationServerEndpointsConfigurer.authenticationManager(authenticationManager)
                .userDetailsService(userService);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory().withClient("user")
                .secret(passwordEncoder.encode("123456"))
                .authorizedGrantTypes("password","refresh_token")
                .accessTokenValiditySeconds(3000)
                .scopes("user");
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.allowFormAuthenticationForClients()
                .tokenKeyAccess("isAuthenticated()")    //获取token
                .checkTokenAccess("isAuthenticated()"); //验证token
    }
}
