package com.privynet;

import jakarta.persistence.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

// ================= MAIN =================
@SpringBootApplication
public class PrivyNetApp {
    public static void main(String[] args) {
        SpringApplication.run(PrivyNetApp.class, args);
        System.out.println("✅ PrivyNet running on http://localhost:8080");
    }

    // Seed default security alerts once on startup if none exist
    @Bean
    ApplicationRunner seedAlerts(AlertRepository alertRepo) {
        return args -> {
            if (alertRepo.count() == 0) {
                String[][] data = {
                    {"SUSPICIOUS_LOGIN",     "Multiple failed login attempts from IP 192.168.1.45 — 7 attempts in 3 minutes",              "HIGH"},
                    {"BRUTE_FORCE_ATTEMPT",  "Repeated password reset requests for user 'admin' from unknown device",                       "HIGH"},
                    {"UNUSUAL_ACCESS",       "User 'David' accessed the system at 2:34 AM — outside normal business hours",                 "MEDIUM"},
                    {"PRIVILEGE_ESCALATION", "User attempted to access restricted admin panel without authorization",                        "MEDIUM"},
                    {"DATA_EXPORT",          "Large data export detected — 500+ records downloaded by a single user in one session",        "MEDIUM"},
                    {"NEW_DEVICE_LOGIN",     "User 'Eve' logged in from an unrecognized device (Chrome / Windows 11)",                      "LOW"},
                    {"SESSION_TIMEOUT",      "3 user sessions expired due to inactivity and were automatically terminated",                  "LOW"},
                    {"ENCRYPTION_VERIFIED",  "AES-128 integrity check passed — all stored messages are securely encrypted",                 "LOW"},
                };
                for (String[] d : data) {
                    Alert a = new Alert();
                    a.setType(d[0]);
                    a.setDescription(d[1]);
                    a.setSeverity(d[2]);
                    alertRepo.save(a);
                }
                System.out.println("🔔 Seeded " + data.length + " default security alerts");
            }
        };
    }
}

// ================= CORS =================
@Configuration
class CorsConfig {
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                        .allowedOrigins("http://localhost:3000")
                        .allowedMethods("*");
            }
        };
    }
}

// ================= ENCRYPTION =================
@Service
class EncryptionService {

    private SecretKey aesKey;
    private PublicKey rsaPublicKey;

    public EncryptionService() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            aesKey = keyGen.generateKey();

            KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
            rsaGen.initialize(2048);
            KeyPair pair = rsaGen.generateKeyPair();
            rsaPublicKey = pair.getPublic();

            System.out.println(" AES + RSA keys generated");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encryptAES(String text) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(text.getBytes()));
        } catch (Exception e) {
            return text;
        }
    }

    public String decryptAES(String text) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(text)));
        } catch (Exception e) {
            return text;
        }
    }

    public String getPublicKey() {
        return Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded());
    }
}

// ================= ENTITIES =================

@Entity
@Table(name = "messages")
class Message {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String sender;
    private String receiver;
    private String content;
    private LocalDateTime timestamp = LocalDateTime.now();

    public Long getId()                      { return id; }
    public void setSender(String sender)     { this.sender = sender; }
    public void setReceiver(String receiver) { this.receiver = receiver; }
    public void setContent(String content)   { this.content = content; }
    public String getSender()                { return sender; }
    public String getReceiver()              { return receiver; }
    public String getContent()               { return content; }
    public LocalDateTime getTimestamp()      { return timestamp; }
}

@Entity
@Table(name = "feedback")
class Feedback {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String content;
    private int upvotes   = 0;   // thumbs up count
    private int downvotes = 0;   // thumbs down count
    private LocalDateTime timestamp = LocalDateTime.now();

    public Long getId()                    { return id; }
    public void setContent(String content) { this.content = content; }
    public String getContent()             { return content; }
    public int getUpvotes()                { return upvotes; }
    public void setUpvotes(int upvotes)    { this.upvotes = upvotes; }
    public int getDownvotes()              { return downvotes; }
    public void setDownvotes(int dv)       { this.downvotes = dv; }
    public LocalDateTime getTimestamp()    { return timestamp; }
}

@Entity
@Table(name = "alerts")
class Alert {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String type;
    private String description;
    private String severity;
    private LocalDateTime timestamp = LocalDateTime.now();

    public Long getId()                           { return id; }
    public void setType(String type)              { this.type = type; }
    public void setDescription(String desc)       { this.description = desc; }
    public void setSeverity(String severity)      { this.severity = severity; }
    public String getType()                       { return type; }
    public String getDescription()                { return description; }
    public String getSeverity()                   { return severity; }
    public LocalDateTime getTimestamp()           { return timestamp; }
}

// ================= REPOSITORIES =================

@Repository
interface MessageRepository extends JpaRepository<Message, Long> {

    @Query("SELECT m FROM Message m WHERE " +
           "(m.sender = :user1 AND m.receiver = :user2) OR " +
           "(m.sender = :user2 AND m.receiver = :user1) " +
           "ORDER BY m.timestamp ASC")
    List<Message> findConversation(
            @Param("user1") String user1,
            @Param("user2") String user2
    );

    // Count only messages sent OR received by this specific user
    @Query("SELECT COUNT(m) FROM Message m WHERE m.sender = :user OR m.receiver = :user")
    long countByUser(@Param("user") String user);
}

@Repository
interface FeedbackRepository extends JpaRepository<Feedback, Long> {}

@Repository
interface AlertRepository extends JpaRepository<Alert, Long> {}

// ================= CONTROLLERS =================

@RestController
@RequestMapping("/api/messages")
class MessageController {

    private final MessageRepository repo;
    private final EncryptionService enc;

    MessageController(MessageRepository repo, EncryptionService enc) {
        this.repo = repo;
        this.enc  = enc;
    }

    // POST /api/messages/send
    @PostMapping("/send")
    public Message send(@RequestBody Map<String, String> body) {
        Message m = new Message();
        m.setSender(body.get("sender"));
        m.setReceiver(body.get("receiver"));
        m.setContent(enc.encryptAES(body.get("content")));  // encrypt before saving
        return repo.save(m);
    }

    // GET /api/messages?user1=Alice&user2=Bob
    // Uses fixed @Query — returns decrypted messages for both users
    @GetMapping
    public List<Map<String, Object>> get(
            @RequestParam String user1,
            @RequestParam String user2) {

        return repo.findConversation(user1, user2)
                .stream()
                .map(m -> {
                    Map<String, Object> map = new HashMap<>();
                    map.put("id",        m.getId());
                    map.put("sender",    m.getSender());
                    map.put("receiver",  m.getReceiver());
                    map.put("content",   enc.decryptAES(m.getContent()));  // decrypt before sending
                    map.put("timestamp", m.getTimestamp().toString());
                    return map;
                })
                .collect(Collectors.toList());
    }

    // GET /api/messages/count             → falls back to total (for admin use)
    @GetMapping("/count")
    public Map<String, Long> count(@RequestParam(required = false) String user) {
        long c = (user != null && !user.isBlank())
                 ? repo.countByUser(user)
                 : repo.count();
        return Map.of("count", c);
    }
}

@RestController
@RequestMapping("/api/feedback")
class FeedbackController {

    private final FeedbackRepository repo;

    FeedbackController(FeedbackRepository repo) {
        this.repo = repo;
    }

    // POST /api/feedback/submit
    @PostMapping("/submit")
    public Feedback submit(@RequestBody Map<String, String> body) {
        Feedback f = new Feedback();
        f.setContent(body.get("content"));
        return repo.save(f);
    }

    // GET /api/feedback
    @GetMapping
    public List<Feedback> all() {
        return repo.findAll();
    }

    // POST /api/feedback/{id}/upvote — increment thumbs up
    @PostMapping("/{id}/upvote")
    public Feedback upvote(@PathVariable Long id) {
        Feedback f = repo.findById(id)
                         .orElseThrow(() -> new RuntimeException("Not found: " + id));
        f.setUpvotes(f.getUpvotes() + 1);
        return repo.save(f);
    }

    // POST /api/feedback/{id}/downvote — increment thumbs down
    @PostMapping("/{id}/downvote")
    public Feedback downvote(@PathVariable Long id) {
        Feedback f = repo.findById(id)
                         .orElseThrow(() -> new RuntimeException("Not found: " + id));
        f.setDownvotes(f.getDownvotes() + 1);
        return repo.save(f);
    }

    // GET /api/feedback/count
    @GetMapping("/count")
    public Map<String, Long> count() {
        return Map.of("count", repo.count());
    }
}

@RestController
@RequestMapping("/api/alerts")
class AlertController {

    private final AlertRepository repo;

    AlertController(AlertRepository repo) {
        this.repo = repo;
    }

    // GET /api/alerts
    @GetMapping
    public List<Alert> all() {
        return repo.findAll();
    }

    // GET /api/alerts/count
    @GetMapping("/count")
    public Map<String, Long> count() {
        return Map.of("count", repo.count());
    }
}

@RestController
@RequestMapping("/api/security")
class SecurityController {

    private final EncryptionService enc;

    SecurityController(EncryptionService enc) {
        this.enc = enc;
    }

    @GetMapping("/public-key")
    public Map<String, String> key() {
        return Map.of("key", enc.getPublicKey());
    }
}