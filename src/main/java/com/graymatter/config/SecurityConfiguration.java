package com.graymatter.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration {


	@Bean
	public UserDetailsService getUserDetails() {
		
		UserDetails admin = User.withUsername("Divyanshu")
				.password(encodePassword().encode("divyanshu"))
				.roles("Admin")
				.build();
		
		UserDetails user1 = User.withUsername("user1")
				.password(encodePassword().encode("user1@2024"))
				.roles("User")
				.build();
		
		UserDetails user2 = User.withUsername("user2")
				.password(encodePassword().encode("user2@2024"))
				.roles("User")
				.build();
			
		
		return new InMemoryUserDetailsManager(admin, user1, user2);
	}
	
	@Bean
    public PasswordEncoder encodePassword() {
        return new BCryptPasswordEncoder();
    }
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//		return http.csrf().disable()
//				.authorizeHttpRequests()
//				.requestMatchers("/demo").permitAll()
//				.and()
//				.authorizeHttpRequests()
//				.requestMatchers("/name/**")
//				.authenticated()
//				.and()
//				.formLogin()
//				.and()
//				.build();
		
		http.csrf().disable()
		.authorizeHttpRequests(auth->
		auth.requestMatchers("/demo").hasAnyRole("User", "Admin")
		.requestMatchers("/**").hasRole("Admin")
//		.requestMatchers("/demo").hasRole("admin")
		.anyRequest().authenticated()
		)
		.formLogin();
		
		return http.build();
		
		
	}
	
}
