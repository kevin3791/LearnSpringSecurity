package com.kevinmcg.learnspringsecurity.webtoken;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.kevinmcg.learnspringsecurity.model.MyUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter{
	
	@Autowired
	private JwtService jwtService;
	
	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String authHeader = request.getHeader("Authorization");
		
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request,  response);
			return;
		} else {
			String jwt = authHeader.substring(7); // get characters after the word 'Bearer ' as this contains the token
			String username = jwtService.extractUsername(jwt);
			
			if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
				// username provided and not already authenticated
				UserDetails userDetails = myUserDetailsService.loadUserByUsername(username);
				
				if (userDetails != null && jwtService.isTokenValid(jwt)) {
					UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());
					// Get the details of the client and store them in the token
					authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
				}
			}
			
			filterChain.doFilter(request,  response);
		}
	}

}
