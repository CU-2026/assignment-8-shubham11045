package com.example.security_application.security;

import com.example.security_application.entity.User;
import com.example.security_application.repository.UserRepository;
import com.example.security_application.utils.JwtUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        String email = oauthUser.getAttribute("email");

        // 1. Check/Save User to Postgres
        User user = userRepository.findByUsername(email).orElseGet(() -> {
            User newUser = new User();
            newUser.setUsername(email);
            newUser.setPassword(""); // No password for OAuth users
            return userRepository.save(newUser);
        });

        // 2. Generate JWT
        String token = jwtUtils.generateToken(user.getUsername());

        // 3. Redirect to Frontend with Token
        // In a real app, you'd pass this via a cookie or a query param
        getRedirectStrategy().sendRedirect(request, response, "http://localhost:3000/callback?token=" + token);
    }


}
