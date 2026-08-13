package com.korrali.eudirp.demo;

import com.korrali.eudirp.mockwallet.MockWallet;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DemoConfig {

    @Bean
    public MockWallet mockWallet() {
        return new MockWallet();
    }
}
