package com.p1.AppConfig;

import java.io.IOException;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
//Bu sınıf, gelen her istekte kullanıcının kimliğini doğrular ve yetkili bir kullanıcı olup olmadığını kontrol eder.

public class JwtTokenValidator extends OncePerRequestFilter {

    /*
     * JWT (JSON Web Token) tabanlı bir kimlik doğrulama sistemi için kullanılır.
     * JwtTokenValidator sınıfı, gelen HTTP isteklerinde bir JWT'yi kontrol eder, doğrular ve kullanıcıyı güvenlik bağlamına ekler.
     * Kullanıcı oturum açtığında sunucu tarafından oluşturulur ve istemciye (browser veya mobil uygulama) gönderilir.
JWT, her HTTP isteğinde kimlik doğrulama amacıyla kullanılır.
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String jwt = request.getHeader(JwtConstant.JWT_HEADER);

        if (jwt != null) {
            jwt = jwt.substring(7);  // Remove "Bearer " prefix sadece token kısmı alınır.
            try {
                SecretKey key = Keys.hmacShaKeyFor(JwtConstant.SECRETE_KEY.getBytes());
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(jwt)
                        .getBody();

                        //JWT Doğrulanır ve Çözülür

                String email = String.valueOf(claims.get("email"));
                String authorities = String.valueOf(claims.get("authorities"));

                //Kullanıcı Bilgileri Alinir

                List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);

                // Create the authentication token
                UsernamePasswordAuthenticationToken authentication = 
                        new UsernamePasswordAuthenticationToken(email, null, auths);
                
                // Set the authentication in the security context
                SecurityContextHolder.getContext().setAuthentication(authentication);

                //Kullanıcı Sisteme Tanıtılır
                /*
                 * authorities bilgisi (örneğin: ROLE_USER,ROLE_ADMIN), kullanıcı yetkileri olarak işlenir.
                    UsernamePasswordAuthenticationToken ile bir kullanıcı kimlik doğrulama nesnesi oluşturulur.
                    SecurityContextHolder ile bu kullanıcı, sisteme "tanıtılır" (artık giriş yapmış kabul edilir).
                 */

                

            } catch (Exception e) {
                throw new BadCredentialsException("Invalid token!");
            }
        }
        
        // Continue the filter chain
        filterChain.doFilter(request, response);
    }
}
