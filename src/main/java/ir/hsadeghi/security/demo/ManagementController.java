package ir.hsadeghi.security.demo;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/management")
public class ManagementController {

    @GetMapping
    public String get(){
        return "GET:: Management controller";
    }
    @PostMapping
    public String post(){
        return "POST:: Management controller";
    }
    @PutMapping
    public String put(){
        return "PUT:: Management controller";
    }
    @DeleteMapping
    public String delete(){
        return "DELETE:: Management controller";
    }

}
