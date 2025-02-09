package net.mikoto.auth.model;

import com.mybatisflex.annotation.Table;
import lombok.Data;

/**
 * @author mikoto
 * DateTime 2025/2/5 - 19:19
 * Create for auth
 * At package net.mikoto.auth.model
 */
@Data
@Table("client")
public class Client {
    private String name;
    private String version;
    private String totpKey;
    private String md5;
}
