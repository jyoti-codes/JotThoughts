package com.secure.notes.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import static org.springframework.security.config.Customizer.withDefaults;

import java.time.LocalDate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;

import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.repositories.UserRepository;
import com.secure.notes.security.jwt.AuthEntryPointJwt;
import com.secure.notes.security.jwt.AuthTokenFilter;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.config.OAuth2LoginSuccessHandler;
import com.secure.notes.models.AppRole;



import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled=true,securedEnabled=true,jsr250Enabled=true)
public class SecurityConfig { 
	
	@Autowired
    private AuthEntryPointJwt unauthorizedHandler;
	
	@Autowired
	@Lazy
    private OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }
	
	/*@Autowired
	private CustomLoggingFilter customLoggingFilter;
	
	@Autowired
	private RequestValidationFilter requestValidationFilter;*/
	
/*	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests((requests) -> requests
    		//.requestMatchers("/contact").permitAll()
    		.requestMatchers("/public/**").permitAll()
    		.requestMatchers("/api/csrf-token/").permitAll()
    		.requestMatchers("/api/auth/public/**").permitAll()
    		.requestMatchers("/api/admin/**").hasRole("ADMIN")
    		//.requestMatchers("/admin/**").denyAll()
    		.anyRequest().authenticated());
    http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
    http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    http.formLogin(withDefaults());
   // http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
   // http.addFilterBefore(customLoggingFilter, UsernamePasswordAuthenticationFilter.class);
   // http.addFilterAfter(requestValidationFilter, CustomLoggingFilter.class);
    http.httpBasic(withDefaults());
    //http.cors(cors-> cors.disable());
    //http.csrf(csrf-> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).ignoringRequestMatchers("/api/auth/public/**"));
    http.csrf(AbstractHttpConfigurer::disable);
   // http.csrf(csrf-> csrf.disable());
    return http.build();
	}*/
	
	 @Bean
	    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
	        http.csrf(csrf ->
	                csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
	                        .ignoringRequestMatchers("/api/auth/public/**")
	        );
	        http.cors();
	        //http.csrf(AbstractHttpConfigurer::disable);
	        http.authorizeHttpRequests((requests)
	                -> requests
	                .requestMatchers("/api/admin/**").hasRole("ADMIN")
	                .requestMatchers("/api/csrf-token").permitAll()
	                .requestMatchers("/api/auth/public/**").permitAll()
	                .requestMatchers("/oauth2/**").permitAll()
	                .anyRequest().authenticated()).oauth2Login(oauth2 -> {
	                	oauth2.successHandler(oAuth2LoginSuccessHandler);
	                });
	        http.exceptionHandling(exception
	                -> exception.authenticationEntryPoint(unauthorizedHandler));
	        http.addFilterBefore(authenticationJwtTokenFilter(),
	                UsernamePasswordAuthenticationFilter.class);
	        http.formLogin(withDefaults());
	        http.httpBasic(withDefaults());
	        return http.build();
	    }
	
	@Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
}
	
	@Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
	/* @Bean
	    public UserDetailsService userDetailsService(DataSource dataSource) {
	       /* InMemoryUserDetailsManager manager =
	                new InMemoryUserDetailsManager();
		 
		 JdbcUserDetailsManager manager =
	                new JdbcUserDetailsManager(dataSource);
	        if (!manager.userExists("user1")) {
	            manager.createUser(
	                    User.withUsername("user1")
	                            .password("{noop}password1")
	                            .roles("USER")
	                            .build()
	            );
	        }
	        if (!manager.userExists("admin")) {
	            manager.createUser(
	                    User.withUsername("admin")
	                            .password("{noop}adminPass")
	                            .roles("ADMIN")
	                            .build()
	            );
	        }
	        return manager;
	    }*/

	@Bean
    public CommandLineRunner initData(RoleRepository roleRepository, UserRepository userRepository,PasswordEncoder passwordEncoder) {
        return args -> {
            Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_USER)));

            Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_ADMIN)));

            if (!userRepository.existsByUserName("user1")) {
                User user1 = new User("user1", "user1@example.com", passwordEncoder.encode("password1"));
                user1.setAccountNonLocked(false);
                user1.setAccountNonExpired(true);
                user1.setCredentialsNonExpired(true);
                user1.setEnabled(true);
                user1.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                user1.setAccountExpiryDate(LocalDate.now().plusYears(1));
                user1.setTwoFactorEnabled(false);
                user1.setSignUpMethod("email");
                user1.setRole(userRole);
                userRepository.save(user1);
            }
            
            if (!userRepository.existsByUserName("admin")) {
                User admin = new User("admin", "admin@example.com", passwordEncoder.encode("adminPass"));
                admin.setAccountNonLocked(true);
                admin.setAccountNonExpired(true);
                admin.setCredentialsNonExpired(true);
                admin.setEnabled(true);
                admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
                admin.setTwoFactorEnabled(false);
                admin.setSignUpMethod("email");
                admin.setRole(adminRole);
                userRepository.save(admin);
            }
            
            if (!userRepository.existsByUserName("newuser")) {
                User admin = new User("newuser", "newuser@example.com", passwordEncoder.encode("newuserPass"));
                admin.setAccountNonLocked(true);
                admin.setAccountNonExpired(true);
                admin.setCredentialsNonExpired(true);
                admin.setEnabled(true);
                admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
                admin.setTwoFactorEnabled(false);
                admin.setSignUpMethod("email");
                admin.setRole(adminRole);
                userRepository.save(admin);
            }
        };
    }

}
