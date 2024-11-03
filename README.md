# MICROBLOG INFRASTRUCTURE SECURITY REVIEW REPORT

## EXECUTIVE SUMMARY

This report reviews the security of Microblog’s AWS cloud infrastructure, identifying critical vulnerabilities and suggesting measures to enhance the overall security posture. The review primarily focused on the Terraform configuration (used to create the cloud infrastructure in AWS) and the source code of the Microblog application deployed on this infrastructure.

## IDENTIFIED VULNERABILITIES

The vulnerabilities are categorized by different sections of the cloud infrastructure and tagged as “CRITICAL”, “HIGH”, “MEDIUM”, and “LOW” to indicate priority and urgency. Below is a diagram created on the draw.io platform for illustration of the initial infrastructure setup.

### 1. Security Group Misconfiguration

- **[CRITICAL] SSH Access (Port 22):** 
  - The security group allows SSH access from anyone online (0.0.0.0/0), exposing the server to potential brute-force attacks.
    
    **Fix:** Specify the expected CIDR block IP address(es) allowed to log in.

- **[HIGH] HTTP Access (Port 80):**
  - Allowing access from 0.0.0.0/0 can expose the application to web-based attacks.
    
    **Fix:**
    - Switch to using port 443 (HTTPS) and obtain an application certificate to encrypt data in transit, enhancing the company's reputation.
    - If port 80 is retained, utilize a Web Application Firewall (WAF) for additional security.

- **[HIGH] Custom Application Port (5000):**
  - Exposing this port to the entire internet can be risky.
    
    **Fix:** Restrict access to known IP addresses or ranges where feasible.

- **[MEDIUM] Overly permissive Egress Traffic:**
  - The egress rule allows all outbound traffic.
    
    **Fix:** Restrict egress traffic unless proven necessary for the application to minimize the attack surface.

### 2. Lack of Network Segmentation

- **[MEDIUM]** 
  - The current architecture uses a single public subnet, increasing the risk of exposure and attack.
    
    **Fix:** Separate resources and place sensitive services in private subnets with restricted access.

### 3. Missing Logging and Monitoring

- **[CRITICAL]** 
  - There is no logging or monitoring solution in the configuration.
    
    **Fix:** Use free and open-source solutions (like Prometheus, Grafana) or paid options (AWS CloudTrail, AWS Config, VPC Flow Logs) for monitoring and compliance.

### 4. Lack of Code Vulnerability Checks / Absence of CI/CD Pipeline

- **[CRITICAL]** 
  - There is no stage for checking the application source code for known vulnerabilities.
    
    **Fix:** 
    - Incorporate scanning of the application’s source code using OWASP dependency check to identify vulnerabilities prior to deployment.
    - Implement a CI/CD pipeline (e.g., Jenkins) for systematic building, testing, and security-checking.

### 5. Lack of Close Monitoring of Login Log Files

- **[CRITICAL]** 
  - A login log file shows signs of SQL attacks and unauthorized access attempts.
    
    **Fix:** 
    - Monitor this log file closely and investigate any suspicious activity.
    - Implement a Web Application Firewall (WAF) to protect against SQL injection attacks.

## IMMEDIATE FIXES IMPLEMENTED

The three most critical vulnerabilities labeled “CRITICAL” were addressed immediately, while the remaining vulnerabilities are recommended for prompt resolution based on their urgency levels.

## MOVING FORWARD

Regular reviews and updates to security configurations are essential to adapt to the evolving threat landscape. Moving forward, the following practices should be adhered to:

- Schedule a follow-up review after implementing the recommended changes.
- Continuously monitor the environment and update security measures as needed.
- Educate the development team on security best practices in cloud deployments.

## CONCLUSION

The current AWS infrastructure of Microblog has several critical vulnerabilities that could expose the application and data to various security threats. By implementing the recommended security measures, in addition to the three implemented during this review, the organization can significantly strengthen its cloud environment and enhance its overall security posture.
