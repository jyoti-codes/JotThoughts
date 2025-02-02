package com.secure.notes;

import java.security.Principal;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class HomeController {
	
	@GetMapping("/hello")
    public String sayHello(Principal principal,Authentication auth,HttpServletRequest request){
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String currentPrincipalName = authentication.getName();
		
		System.out.println("SecurityContextHolder.getContext().getAuthentication() USER :"+currentPrincipalName);
		System.out.println("Principal USER :"+principal.getName());
		System.out.println("Authentication USER :"+auth.getName());
		Principal principal2 = request.getUserPrincipal();
		System.out.println("request.getUserPrincipal() USER :"+principal2.getName());
        return "Hello";
    }
	
	@GetMapping("/contact")
    public String contactUs(){
        return "Contact Us";
    }

}
