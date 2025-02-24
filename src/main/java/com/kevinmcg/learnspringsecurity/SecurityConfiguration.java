package com.kevinmcg.learnspringsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.kevinmcg.learnspringsecurity.model.MyUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
	
	@Autowired
	private MyUserDetailsService myUserDetailsService;
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity
				.csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(registry -> {
					registry.requestMatchers("/home", "/register/**").permitAll();
					registry.requestMatchers("/admin/**").hasRole("ADMIN");
					registry.requestMatchers("/user/**").hasRole("USER");
					registry.anyRequest().authenticated();
		
				})
		//.formLogin(formLogin ->	formLogin.permitAll())
		.formLogin(httpSecurityFormLoginConfigurer -> 
					httpSecurityFormLoginConfigurer.loginPage("/login")
					.successHandler(new AuthenticationSuccessHandler())
					.permitAll())		
		.build();
	}
	
//	@Bean
//	public UserDetailsService userDetailsService() {
//		UserDetails normalUser = User.builder()
//				.username("kevin")
//				.password("$2a$12$4f.eGTldfpjSan/ylYpHJeH8t7hGDV9NLG4i/.23WyN56DJT7gGJu")
//				.roles("USER")
//				.build();
//		
//		UserDetails adminUser = User.builder()
//				.username("admin")
//				.password("$2a$12$Cm7k82k0rTED0qA9zmuBUOGcbYsyHpU2/Q4A0JCFHAUB2YqNkw3nK")
//				.roles("ADMIN", "USER")
//				.build();
//		
//		return new InMemoryUserDetailsManager(normalUser, adminUser);
//
//	}
	
	@Bean
	public UserDetailsService userDetailsService() {
		return myUserDetailsService;
	}
	
	@Bean
	/*
	 * An AuthenticationProvider is responsible for authenticating a user's credentials 
	 * and returning an Authentication object that represents the authenticated user.
	 */
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(myUserDetailsService);
		provider.setPasswordEncoder(passwordEncoder());
		
		return provider;
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
