package com.p1.AppConfig;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.boot.autoconfigure.integration.IntegrationProperties.Management;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
/*
 *  Bu sınıfın bir konfigürasyon sınıfı olduğunu belirtir. Yani, uygulamanın yapılandırılmasında kullanılır.
 */
@EnableWebSecurity


public class AppConfig {
    /*
     *  1.)Uygulamanın güvenlik ayarlarını yapar.
        HttpSecurity: Web güvenliğiyle ilgili ayarları özelleştirmek için kullanılır.
        @Bean: Bu metodu bir "bean" olarak tanımlar, yani Spring tarafından yönetilir ve gerektiğinde kullanılır.

        2.)SessionCreationPolicy.STATELESS: Sunucunun kullanıcı için bir oturum (session) oluşturmasını engeller.
        Bu,modern API'lerde yaygın bir durumdur çünkü oturum yerine JWT (JSON Web Token) gibi stateless (durumsuz) yöntemler kullanılır.
        nedenleri -> HTTP Protokolü Durumsuzdur,Stateless API,Microservices Uyumluluğu

        3.)requestMatchers("/api/**").authenticated(): "/api/" ile başlayan tüm isteklerin kimlik doğrulaması yapılmasını zorunlu kılar.
        AnyRequest().permitAll(): Diğer tüm isteklere erişim izni verir.

        4.)CSRF (Cross-Site Request Forgery):bir kullanıcının bilgisi veya isteği olmadan,
        kimliğini kullanarak yetkili bir işlemi gerçekleştirmeye zorlandığı bir güvenlik saldırısı türüdür.
        Bu saldırı, bir web uygulamasının, kullanıcının oturumunu kötüye kullanarak işlem yapmasını sağlar.

        5.)CORS: Bir kaynağa (örneğin bir API'ye) farklı bir domain'den (örneğin bir frontend uygulamasından) erişim izni verir.
        http://localhost:3000: React uygulaması.
        http://localhost:5173: Vite ile çalışan bir uygulama.
        http://localhost:4200: Angular uygulaması.


     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.sessionManagement(Management -> Management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(Authorize -> Authorize.requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll())
            .addFilterBefore(new JwtTokenValidator(), BasicAuthenticationFilter.class)
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(configurationSource()));

            
        return http.build();

    }

    private CorsConfigurationSource corsConfigurationSource(){
        return new CorsConfigurationSource() {

            @Override
            @Nullable
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration cfg = new CorsConfiguration();
                cfg.setAllowedOrigins(Arrays.asList(
                    "http://localhost:3000/",
                    "http://localhost:5173/",
                    "http://localhost:4200/"

                ));

                cfg.setAllowedMethods(Collections.singletonList("*"));

                // tum http methodlarina izin verir

                cfg.setAllowCredentials(true);

                // Kimlik doğrulama bilgilerinin (örneğin, çerez veya token) isteklerde gönderilmesine izin verir.

                cfg.setAllowedHeaders(Collections.singletonList("*"));

                cfg.setExposedHeaders(Arrays.asList("Authorization"));

                //API'nin döndürdüğü yanıtta Authorization başlığının görünmesine izin verir.

                cfg.setMaxAge(3600L);

                //CORS kurallarının tarayıcı tarafından 1 saat (3600 saniye) boyunca önbellekte saklanmasını sağlar.


                return cfg;
         
            }
            
        };

        
    }

    /*
     * PasswordEncoder:
    Şifreleri (parolaları) güvenli bir şekilde hashlemek (şifrelemek) için kullanılan bir arayüzdür.
    Spring Security'de şifrelerin saklanması ve doğrulanması sırasında kullanılır.
    Farklı hashing algoritmalarıyla uygulanabilir (örneğin, BCrypt, PBKDF2, Argon2).

    BCryptPasswordEncoder:
    Bu metotta döndürülen nesne, Spring Security'nin sağladığı bir BCryptPasswordEncoder örneğidir.
    BCrypt bir şifreleme algoritmasıdır ve şifrelerin güvenli bir şekilde saklanmasını sağlar.
    
    Şifreleri geri döndürülemez şekilde hashler.Her hash için bir salt kullanır (aynı şifreler için farklı hashler üretir).
    Zamanla daha güçlü hale gelen bir algoritmadır.
     */
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
