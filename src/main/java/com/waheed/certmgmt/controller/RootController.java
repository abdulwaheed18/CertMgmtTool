package com.waheed.certmgmt.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * This controller handles application errors to support the Single Page Application (SPA).
 * When a 404 Not Found error occurs (e.g., a user refreshes a page on a client-side route),
 * this controller catches the error and forwards the request to the main index.html page.
 * This allows the client-side React router to take over and display the correct view.
 */
@Controller
public class RootController implements ErrorController {

    /**
     * Handles requests dispatched to the /error path by the servlet container.
     *
     * @param request The incoming HTTP request, containing error attributes.
     * @return A string indicating how to handle the request. For 404 errors, it's a forward
     * to "/index.html". For other errors, it can point to a generic error view.
     */
    @RequestMapping("/error")
    public String handleError(HttpServletRequest request) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);

        if (status != null) {
            Integer statusCode = Integer.valueOf(status.toString());

            // For HTTP 404 Not Found errors, forward to the SPA's entry point.
            if (statusCode == HttpStatus.NOT_FOUND.value()) {
                return "forward:/index.html";
            }
        }

        // For all other errors (e.g., 500 Internal Server Error), this will let Spring Boot's
        // default error handling take over, which is often sufficient.
        // If you had a custom error.html page, it would be rendered here.
        return "error";
    }
}
