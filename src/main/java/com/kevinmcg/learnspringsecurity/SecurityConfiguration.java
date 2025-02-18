package com.kevinmcg.learnspringsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.authorizeHttpRequests(registry -> {
			registry.requestMatchers("/home").permitAll();
			registry.requestMatchers("/admin/**").hasRole("ADMIN");
			registry.requestMatchers("/user/**").hasRole("USER");
			registry.anyRequest().authenticated();

		})
		.formLogin(formLogin ->	formLogin.permitAll())	
		.build();
	}
	
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails normalUser = User.builder()
				.username("kevin")
				.password("$2a$12$4f.eGTldfpjSan/ylYpHJeH8t7hGDV9NLG4i/.23WyN56DJT7gGJu")
				.roles("USER")
				.build();
		
		UserDetails adminUser = User.builder()
				.username("admin")
				.password("$2a$12$Cm7k82k0rTED0qA9zmuBUOGcbYsyHpU2/Q4A0JCFHAUB2YqNkw3nK")
				.roles("ADMIN", "USER")
				.build();
		
		return new InMemoryUserDetailsManager(normalUser, adminUser);

	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
