package net.mikoto.auth.controller;

import com.alibaba.fastjson2.JSONObject;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author mikoto
 * DateTime 2025/2/5 - 18:36
 * Create for auth
 * At package net.mikoto.auth.controller
 */
@RestController
@RequestMapping("/card")
public class CardRestController {
    @RequestMapping("/create")
    public JSONObject createCard() {
    }
}
