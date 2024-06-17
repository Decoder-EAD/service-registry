package com.ead.service.registry.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
class WebSecurityConfig(

    @Value("\${ead.service-registry.username}")
    private val username: String,

    @Value("\${ead.service-registry.password}")
    private val password: String

) {

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http.httpBasic(Customizer.withDefaults())
        http.authorizeHttpRequests { auth -> auth.anyRequest().authenticated() }
        http.csrf { csrf -> csrf.disable() }
        http.formLogin(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    fun userDetailsService(): InMemoryUserDetailsManager = InMemoryUserDetailsManager(
        User.withUsername(username)
            .password(passwordEncoder().encode(password))
            .roles("ADMIN")
            .build()
    )

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

}