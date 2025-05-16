import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { LinkIcon } from "lucide-react";

const sourcesData = [
  { id: 1, text: "Cross Site Scripting (XSS) Reflected - DVWA 1.10 Security Level Low - - Ilmu Bersama", url: "https://ilmubersama.com/2022/03/12/cross-site-scripting-xss-reflected-dvwa-1-10-security-level-low/" },
  { id: 2, text: "All labs | Web Security Academy - PortSwigger", url: "https://portswigger.net/web-security/all-labs" },
  { id: 3, text: "How Websites Work (HTML/JS & Web Security) - How the web works - YouTube", url: "https://www.youtube.com/watch?v=iWoiwFRLV4I" },
  { id: 4, text: "Access control vulnerabilities and privilege escalation | Web ...", url: "https://portswigger.net/web-security/access-control" },
  { id: 5, text: "What is SSRF (Server-side request forgery)? Tutorial & Examples | Web Security Academy", url: "https://portswigger.net/web-security/ssrf" },
  { id: 6, text: "HTTP in detail - gadoi/tryhackme - GitHub", url: "https://github.com/gadoi/tryhackme/blob/main/HTTP%20in%20detail" },
  { id: 7, text: "Help http resquest, set the id parameter to 1 in the URL field, HELP plz : r/tryhackme - Reddit", url: "https://www.reddit.com/r/tryhackme/comments/1gfmn3n/help_http_resquest_set_the_id_parameter_to_1_in/" },
  { id: 8, text: "Web Security - Darpa Presentation - Carnegie Mellon University", url: "https://users.ece.cmu.edu/~dbrumley/courses/18487-f13/powerpoint/17-web-security1.pdf" },
  { id: 9, text: "What is stored XSS (cross-site scripting)? Tutorial & Examples | Web Security Academy", url: "https://portswigger.net/web-security/cross-site-scripting/stored" },
  { id: 10, text: "Tag: XSS dvwa security low - Ilmu Bersama", url: "https://ilmubersama.com/tag/xss-dvwa-security-low/" },
  { id: 11, text: "HTTP in Detail - TryHackMe", url: "https://tryhackme.com/room/httpindetail" },
  { id: 12, text: "Exploiting SSRF vulnerability [Server-Side Request Forgery] - Vaadata", url: "https://www.vaadata.com/blog/exploiting-the-ssrf-vulnerability/" },
  { id: 13, text: "Hi everybody. Here is a walkthrough of the fifth room in the Web Fundamentals path, called Walking An Application. A very fun room in my opinion, where we are only using the built-in tools in our browser to find security issues in the web application TryHackMe has provided. Enjoy! - Reddit", url: "https://www.reddit.com/r/tryhackme/comments/1ayxqm4/hi_everybody_here_is_a_walkthrough_of_the_fifth/" },
  { id: 14, text: "TryHackMe How Websites Work Official Walkthrough - YouTube", url: "https://www.youtube.com/watch?v=0vIPUKK_8qs" },
  { id: 15, text: "File Inclusion Vulnerabilities - Metasploit Unleashed - OffSec", url: "https://www.offsec.com/metasploit-unleashed/file-inclusion-vulnerabilities/" },
  { id: 16, text: "OWASP Juice Shop - GitHub", url: "https://github.com/juice-shop" },
  { id: 17, text: "Mitigating OWASP Web Application Risk: Server Side Request Forgery (SSRF) using F5 Advanced WAF", url: "https://community.f5.com/kb/technicalarticles/mitigating-owasp-web-application-risk-server-side-request-forgery-ssrf-using-f5-/340260" },
  { id: 18, text: "NahamStore - TryHackMe", url: "https://tryhackme.com/room/nahamstore" },
  { id: 19, text: "Mitigating OWASP Web Application Risk: SSRF Attack using F5 XC Platform", url: "https://community.f5.com/kb/technicalarticles/mitigating-owasp-web-application-risk-ssrf-attack-using-f5-xc-platform/309635" },
  { id: 20, text: "OWASP Juice Shop: Probably the most modern and sophisticated insecure web application - GitHub", url: "https://github.com/juice-shop/juice-shop" },
  { id: 21, text: "1. DVWA command injection (C) - DCC/FCUP", url: "https://www.dcc.fc.up.pt/~edrdo/aulas/qses/lectures/lab1/" },
  { id: 22, text: "Server Side Request Forgery (SSRF) Attacks & How to Prevent Them - Bright Security", url: "https://brightsec.com/blog/ssrf-server-side-request-forgery/" },
  { id: 23, text: "Cross Site Scripting (XSS) - OWASP Foundation", url: "https://owasp.org/www-community/attacks/xss/" },
  { id: 24, text: "Detailed Analysis of Cross-Site Scripting (XSS) security exploit paths. - DevCentral", url: "https://community.f5.com/kb/technicalarticles/cross-site-scripting-xss-exploit-paths/275166" },
  { id: 25, text: "Web Security Research Papers - PortSwigger Research", url: "https://portswigger.net/research" },
  { id: 26, text: "Analisis Perbandingan Kinerja Tool Website Directory Brute Force dengan Target Website DVWA - ResearchGate", url: "https://www.researchgate.net/publication/366644400_Analisis_Perbandingan_Kinerja_Tool_Website_Directory_Brute_Force_dengan_Target_Website_DVWA" },
  { id: 27, text: "Releases · juice-shop/juice-shop - GitHub", url: "https://github.com/juice-shop/juice-shop/releases/" },
  { id: 28, text: "Top 5 (deliberately) vulnerable web applications to practice your skills on - Infosec", url: "https://www.infosecinstitute.com/resources/penetration-testing/top-5-deliberately-vulnerable-web-applications-to-practice-your-skills-on/" },
  { id: 29, text: "What is Clickjacking? Tutorial & Examples | Web Security Academy - PortSwigger", url: "https://portswigger.net/web-security/clickjacking" },
  { id: 30, text: "What is Clickjacking | Attack Example | X-Frame-Options Pros & Cons | Imperva", url: "https://www.imperva.com/learn/application-security/clickjacking/" },
  { id: 31, text: "khangtictoc/DVWA_ModSecurity_Deployment: Deploy DVWA Webserver + ModSecurity + Scanner for researching rules. Auto deployment scripts are supported - GitHub", url: "https://github.com/khangtictoc/DVWA_ModSecurity_Deployment" },
  { id: 32, text: "Damn Vulnerable Web Application - Wikipedia", url: "https://en.wikipedia.org/wiki/Damn_Vulnerable_Web_Application" },
  { id: 33, text: "What is Cross-site Scripting (XSS): prevention and fixes - Acunetix", url: "https://www.acunetix.com/websitesecurity/cross-site-scripting/" },
  { id: 34, text: "Web Hacker Basics 04 (Local and Remote File Inclusion) - YouTube", url: "https://www.youtube.com/watch?v=htTEfokaKsM" },
  { id: 35, text: "Scan DVWA Application for Vulnerabilities | Acunetix", url: "https://www.acunetix.com/blog/docs/scanning-dvwa-with-acunetix/" },
  { id: 36, text: "All learning materials | Web Security Academy - PortSwigger", url: "https://portswigger.net/web-security/all-materials" },
  { id: 37, text: "OWASP Juice Shop - Probably the most modern and sophisticated insecure web application", url: "https://juice-shop.github.io/juice-shop/" },
  { id: 38, text: "Web Application Basics - TryHackMe", url: "https://tryhackme.com/room/webapplicationbasics" },
  { id: 39, text: "DVWA - Insecure CAPTCHA - Pentest Journeys", url: "https://cspanias.github.io/posts/DVWA-Insecure-CAPTCHA/" },
  { id: 40, text: "Official OWASP Juice Shop tutorials on UI customization and system integration - GitHub", url: "https://github.com/juice-shop/juice-shop-tutorials" },
  { id: 41, text: "OWASP Vulnerable Web Applications Directory", url: "https://owasp.org/www-project-vulnerable-web-applications-directory/" },
  { id: 42, text: "Damn Vulnerable Web Applications - - AccuKnox", url: "https://help.accuknox.com/getting-started/dvwa/" },
  { id: 43, text: "All Web Security Academy topics - PortSwigger", url: "https://portswigger.net/web-security/all-topics" },
  { id: 44, text: "dirb | Kali Linux Tools", url: "https://www.kali.org/tools/dirb/" },
  { id: 45, text: "Clickjacking Attacks and How to Prevent Them - Auth0", url: "https://auth0.com/blog/preventing-clickjacking-attacks/" },
  { id: 46, text: "Burp Clickbandit: A JavaScript based clickjacking PoC generator | PortSwigger Research", url: "https://portswigger.net/research/burp-clickbandit-a-javascript-based-clickjacking-poc-generator" },
  { id: 47, text: "OWASP Juice Shop", url: "https://owasp.org/www-project-juice-shop/" },
  { id: 48, text: "How Websites Work - TryHackMe", url: "https://tryhackme.com/room/howwebsiteswork" },
  { id: 49, text: "Local File Inclusion (LFI): Understanding and Preventing LFI Attacks - Bright Security", url: "https://brightsec.com/blog/local-file-inclusion-lfi/" },
  { id: 50, text: "juice-shop/SOLUTIONS.md at master - GitHub", url: "https://github.com/juice-shop/juice-shop/blob/master/SOLUTIONS.md" },
  { id: 51, text: "Burp Clickbandit - PortSwigger", url: "https://portswigger.net/burp/documentation/desktop/tools/clickbandit" },
  { id: 52, text: "0xneobyte/TryHackMe-Learning-Path-From-Beginner-to-Expert - GitHub", url: "https://github.com/tharushkadinujaya05/TryHackMe-Learning-Path-From-Beginner-to-Expert" },
  { id: 53, text: "Using Burp to find Clickjacking Vulnerabilities - PortSwigger", url: "https://portswigger.net/support/using-burp-to-find-clickjacking-vulnerabilities" },
  { id: 54, text: "DVWA - Damn Vulnerable Web App Test Drive - Edgenexus", url: "https://www.edgenexus.io/dvwa/" },
  { id: 55, text: "What is reflected XSS (cross-site scripting)? Tutorial & Examples | Web Security Academy", url: "https://portswigger.net/web-security/cross-site-scripting/reflected" },
  { id: 56, text: "Pwning OWASP Juice Shop: Untitled", url: "https://pwning.owasp-juice.shop/" },
  { id: 57, text: "digininja/DVWA: Damn Vulnerable Web Application (DVWA) - GitHub", url: "https://github.com/digininja/DVWA" },
  { id: 58, text: "Getting started | Web Security Academy - PortSwigger", url: "https://portswigger.net/web-security/getting-started" },
  { id: 59, text: "25 Days of Cyber Security - TryHackMe", url: "https://tryhackme.com/room/learncyberin25days" },
  { id: 60, text: "OWASP Developer Guide | Juice Shop", url: "https://owasp.org/www-project-developer-guide/release/training_education/vulnerable_applications/juice_shop/" },
  { id: 61, text: "Burp Suite documentation - contents - PortSwigger", url: "https://portswigger.net/burp/documentation/contents" },
  { id: 62, text: "Pwning OWASP Juice Shop - GRIET SDC", url: "https://grietsdc.in/downloads/nasscom161121/pwning%20-%20JuiceShop.pdf" },
  { id: 63, text: "potatosalad/dvwa - GitHub", url: "https://github.com/potatosalad/dvwa" },
  { id: 64, text: "HTTP in Detail | TryHackMe Full Walkthrough - YouTube", url: "https://www.youtube.com/watch?v=JYqZVGG7RPI" },
  { id: 65, text: "File Inclusion Attacks – Understanding LFI and RFI Exploits - Indusface", url: "https://www.indusface.com/learning/file-inclusion-attacks-lfi-rfi/" },
  { id: 66, text: "What is Burp Extension? - Indusface Learning", url: "https://www.indusface.com/learning/what-is-burp-extension/?amp" },
  { id: 67, text: "www-project-developer-guide/draft/09-training-education/01-vulnerable-apps/01-juice-shop.md at main - GitHub", url: "https://github.com/OWASP/www-project-developer-guide/blob/main/draft/09-training-education/01-vulnerable-apps/01-juice-shop.md" },
  { id: 68, text: "Stanford Web Security Research", url: "https://seclab.stanford.edu/websec/" },
  { id: 69, text: "HTTP in detail | TryHackMe Walkthrough - YouTube", url: "https://www.youtube.com/watch?v=rNuZ6f1i2Fw" },
  { id: 70, text: "What is XXE (XML external entity) injection? Tutorial & Examples | Web Security Academy", url: "https://portswigger.net/web-security/xxe" },
  { id: 71, text: "COMP4108 — Fall 2012 - Carleton Computer Security Lab (CCSL)", url: "https://ccsl.carleton.ca/~dmccarney/COMP4108/a4.html" },
  { id: 72, text: "Testing for clickjacking - PortSwigger", url: "https://portswigger.net/burp/documentation/desktop/testing-workflow/testing-for-clickjacking" },
  { id: 73, text: "Metasploitable 2 Exploitability Guide - Docs @ Rapid7", url: "https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/" },
  { id: 74, text: "Application Security Blog - AppSec news, trends, tips and insights", url: "https://www.contrastsecurity.com/security-influencers" },
  { id: 75, text: "What is RFI | Remote File Inclusion Example & Mitigation Methods | Imperva", url: "https://www.imperva.com/learn/application-security/rfi-remote-file-inclusion/" },
  { id: 76, text: "All repositories - OWASP Juice Shop - GitHub", url: "https://github.com/orgs/juice-shop/repositories" },
  { id: 77, text: "OWASP Top Ten", url: "https://owasp.org/www-project-top-ten/" },
  { id: 78, text: "Web Fundamentals Path | TryHackMe - YouTube", url: "https://www.youtube.com/watch?v=uurqn1pNeOI" },
  { id: 79, text: "Vulnversity - TryHackMe", url: "https://tryhackme.com/room/vulnversity" },
  { id: 80, text: "VULNERABILITY DETECTION AND EXPLOITATION OF WEB APPLICATIONS Ishwinder Singh 140971 isingh2@student.concordia.ab.ca A Project Su", url: "https://era.library.ualberta.ca/items/abc2c1a9-1adf-4dca-889f-c36eaaf2de5e/view/22f18754-f6b4-4144-8967-b29ce0819448/Singh-I_2020_Fall_MISSM.pdf" },
  { id: 81, text: "10 Practical scenarios for XSS attacks | Pentest-Tools.com Blog", url: "https://pentest-tools.com/blog/xss-attacks-practical-scenarios" },
  { id: 82, text: "OWASP Top 10 Vulnerabilities - Veracode", url: "https://www.veracode.com/security/owasp-top-10/" },
  { id: 83, text: "File Inclusion Vulnerabilities: What are they and how do they work? - Bright Security", url: "https://brightsec.com/blog/file-inclusion-vulnerabilities/" },
  { id: 84, text: "Cross Site Request Forgery (CSRF) - OWASP Foundation", url: "https://owasp.org/www-community/attacks/csrf" },
  { id: 85, text: "SQL Injection Cheat Sheet - Invicti", url: "https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/" },
  { id: 86, text: "Bypassing client-side controls - PortSwigger", url: "https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/client-side-controls" },
  { id: 87, text: "StumbleSec - TryHackMe", url: "https://tryhackme.com/p/StumbleSec" },
  { id: 88, text: "Burp Extension Mini series | Autorize | Bug Bounty Service LLC - YouTube", url: "https://www.youtube.com/watch?v=_d4MzLLtrTY" },
  { id: 89, text: "Content Discovery - TryHackMe Junior Penetration Tester 3.2 - YouTube", url: "https://www.youtube.com/watch?v=_KFx-loyMK4" },
  { id: 90, text: "pac.sec - TryHackMe", url: "https://tryhackme.com/p/pac.sec" },
  { id: 91, text: "Testing web-based attacks using DVWA - Packt", url: "https://www.packtpub.com/en-SG/product/security-monitoring-with-wazuh-9781837632152/chapter/chapter-1-intrusion-detection-system-ids-using-wazuh-2/section/testing-web-based-attacks-using-dvwa-ch02lvl1sec07" },
  { id: 92, text: "What is SSRF (server-side request forgery)? | Tutorial & examples - Snyk Learn", url: "https://learn.snyk.io/lesson/ssrf-server-side-request-forgery/" },
  { id: 93, text: "TryHackMe's 'Content Studio' Has Arrived!", url: "https://tryhackme.com/resources/blog/content-studio-launch" },
  { id: 94, text: "Remote File Inclusion (RFI) - Invicti", url: "https://www.invicti.com/learn/remote-file-inclusion-rfi/" },
  { id: 95, text: "A Pentester's Guide to File Inclusion - Cobalt", url: "https://www.cobalt.io/blog/a-pentesters-guide-to-file-inclusion" },
  { id: 96, text: "Web Security Blog - PortSwigger", url: "https://portswigger.net/blog" },
  { id: 97, text: "Testing for Clickjacking - WSTG - v4.1 | OWASP Foundation", url: "https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/09-Testing_for_Clickjacking" },
  { id: 98, text: "Testing access controls with Burp Suite - PortSwigger", url: "https://portswigger.net/burp/documentation/desktop/testing-workflow/access-controls" },
  { id: 99, text: "Sqlmap, the Tool for Detecting and Exploiting SQL Injections - Vaadata", url: "https://www.vaadata.com/blog/sqlmap-the-tool-for-detecting-and-exploiting-sql-injections/" },
  { id: 100, text: "A DYNAMIC TOOL FOR DETECTION OF XSS ATTACKS IN A REAL-TIME ENVIRONMENT - ARPN Journals", url: "http://www.arpnjournals.com/jeas/research_papers/rp_2015/jeas_0615_2143.pdf" },
  { id: 101, text: "Web Security Academy: Free Online Training from PortSwigger", url: "https://portswigger.net/web-security" },
  { id: 102, text: "dvwa | Kali Linux Tools", url: "https://www.kali.org/tools/dvwa/" },
  { id: 103, text: "TryHackMe - HTTP in Detail - YouTube", url: "https://www.youtube.com/watch?v=YTaMCuOFXr0" },
  { id: 104, text: "Brute Force Heroes - TryHackMe", url: "https://tryhackme.com/room/bruteforceheroes" },
  { id: 105, text: "Pwning OWASP Juice Shop - Leanpub", url: "https://leanpub.com/juice-shop" },
  { id: 106, text: "Local File Inclusion (LFI) - Invicti", url: "https://www.invicti.com/learn/local-file-inclusion-lfi/" },
  { id: 107, text: "DVWA - SQL Injection - Pentest Journeys", url: "https://cspanias.github.io/posts/DVWA-SQL-Injection/" },
  { id: 108, text: "Bypassing XSS filters by enumerating permitted tags and attributes using Burp Suite", url: "https://www.youtube.com/watch?v=lSwasvUDR6c" },
  { id: 109, text: "OWASP Top 10 API Security Risks – 2023", url: "https://owasp.org/API-Security/editions/2023/en/0x11-t10/" },
  { id: 110, text: "DSOMM and Juice Shop User Day", url: "https://dsomm.owasp.org/userday" },
  { id: 111, text: "OWASP Cloud-Native Application Security Top 10", url: "https://owasp.org/www-project-cloud-native-application-security-top-10/" },
  { id: 112, text: "Getting started with Burp Suite Professional / Community Edition - PortSwigger", url: "https://portswigger.net/burp/documentation/desktop/getting-started" },
  { id: 113, text: "Obtaining a token sample - PortSwigger", url: "https://portswigger.net/burp/documentation/desktop/tools/sequencer/sample" },
  { id: 114, text: "OWASP Damn Vulnerable Web Sockets", url: "https://owasp.org/www-project-damn-vulnerable-web-sockets/" },
  { id: 115, text: "Subdomain Enumeration - TryHackMe Junior Penetration Tester 3.3 - YouTube", url: "https://www.youtube.com/watch?v=nXu1vDqe4lM" },
  { id: 116, text: "What is Autorize Burpsuite Plugin and How to Use it? - Payatu", url: "https://payatu.com/blog/what-is-authorize-burpsuite-plugin-how-to-use-it/" },
  { id: 117, text: "Hydra - How to Crack a Remote Authentication Service - TryHackMe", url: "https://tryhackme.com/resources/blog/hydra" },
  { id: 118, text: "Tutorial- SQLmap First we start the web application (Damn Vulnerable Web App) - Open Kali Linux (located in /virtual)", url: "http://www.cs.toronto.edu/~arnold/427/16s/csc427_16s/tutorials/sqlmap/SQLMap%20Tutorial.pdf" },
  { id: 119, text: "The OWASP Top Ten 2025", url: "https://www.owasptopten.org/" },
  { id: 120, text: "Learn Cyber Security | TryHackMe Cyber Training", url: "https://tryhackme.com/" },
  { id: 121, text: "HTTP - TryHackMe", url: "https://tryhackme.com/p/HTTP" },
  { id: 122, text: "Authentication vulnerabilities | Web Security Academy - PortSwigger", url: "https://portswigger.net/web-security/authentication" },
  { id: 123, text: "Burpsuite for Pentester: Autorize - Hacking Articles", url: "https://www.hackingarticles.in/burpsuite-for-pentester-autorize/" },
  { id: 124, text: "Using DVWA to Exploit Top OWASP Risks - Sprocket Security", url: "https://www.sprocketsecurity.com/blog/owasp-top-10-risks-of-2022" },
  { id: 125, text: "Content Discovery: Understanding Your Web Attack Surface | Praetorian", url: "https://www.praetorian.com/blog/content-discovery-understanding-your-web-attack-surface/" },
  { id: 126, text: "PortSwigger: Web Application Security, Testing, & Scanning", url: "https://portswigger.net/" },
  { id: 127, text: "Injection vulnerabilities - Universidade do Porto", url: "https://www.dcc.fc.up.pt/~edrdo/aulas/qses/lectures/qses-03-injection.pdf" },
  { id: 128, text: "Cyber Lab for Beginners Learning Web Application Security DVWA - YouTube", url: "https://www.youtube.com/watch?v=yYhTYBRe5Bg" },
  { id: 129, text: "Maximizing IDOR Detection with Burp Suite's Autorize | Black Hat Ethical Hacking", url: "https://www.blackhatethicalhacking.com/articles/maximizing-idor-detection-with-burp-suites-autorize/" },
  { id: 130, text: "IamCarron/DVWA-Script: Automate the setup of Damn Vulnerable Web Application (DVWA) with this Bash script. It ensures a smooth installation, adapting to the system's language and handling dependencies effortlessly. The script simplifies the process of cloning DVWA from GitHub, configuring MySQL, adjusting PHP settings, and restarting Apache.", url: "https://github.com/IamCarron/DVWA-Script" },
  { id: 131, text: "westwardfishd - TryHackMe", url: "https://tryhackme.com/p/westwardfishd" },
  { id: 132, text: "Scanning the Damn Vulnerable Web App with StackHawk", url: "https://www.stackhawk.com/blog/scanning-the-damn-vulnerable-web-app-with-stackhawk/" },
  { id: 133, text: "Blog - TryHackMe", url: "https://tryhackme.com/resources/blog" },
  { id: 134, text: "Introduction to Web Hacking - TryHackMe", url: "https://tryhackme.com/module/intro-to-web-hacking" },
  { id: 135, text: "Free TryHackMe Training: The Ultimate Guide for Beginners", url: "https://tryhackme.com/resources/blog/free_path" },
  { id: 136, text: "OWASP Juice Shop", url: "http://juice-shop.herokuapp.com/" },
  { id: 137, text: "Content discovery - PortSwigger", url: "https://portswigger.net/burp/documentation/desktop/tools/engagement-tools/content-discovery" },
  { id: 138, text: "K000146894: How to mitigate OWASP Top Ten A06:2021 – Vulnerable and Outdated Components. - MyF5 | Support", url: "https://my.f5.com/manage/s/article/K000146894" },
  { id: 139, text: "Bypassing client-side controls with Burp Suite - YouTube", url: "https://www.youtube.com/watch?v=znstcw4wMNg" },
  { id: 140, text: "OWASP Top 10 for Large Language Model Applications", url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/" },
  { id: 141, text: "juice-shop/SOLUTIONS.md at master - GitHub", url: "https://github.com/DataDog/juice-shop/blob/master/SOLUTIONS.md" },
  { id: 142, text: "66. B.Tech CSE-2021.pdf - Gurugram - naac - SGT University", url: "https://naac.sgtuniversity.ac.in/naac/DVV_CL_CR/DVV_CL_CR1/NEW%20SYLLABUS/66.%20B.Tech%20CSE-2021.pdf" },
  { id: 143, text: "Laboratory Exercise – Cyber Basics – Web Application Security: SQL Injection Lab", url: "https://www.uscyberrange.org/wp-content/uploads/2023/02/3_SQL-Injection-lab.pdf" },
  { id: 144, text: "Finding Access Control Vulnerabilities with Autorize - Black Hills Information Security, Inc.", url: "https://www.blackhillsinfosec.com/finding-access-control-vulnerabilities-with-autorize/" },
  { id: 145, text: "How to Exploit DVWA Blind SQL Injection (SQLi) with SQLMap and Burp Suite - GitHub Gist", url: "https://gist.github.com/kevinobama/d8401b0b006fe1375b07d51fc6792b70" },
  { id: 146, text: "Testing for clickjacking using Burp Suite - YouTube", url: "https://www.youtube.com/watch?v=OQRYDAG0hGE" },
  { id: 147, text: "nima - TryHackMe", url: "https://tryhackme.com/p/nima" },
  { id: 148, text: "Command Injection: How it Works and 5 Ways to Protect Yourself - Bright Security", url: "https://brightsec.com/blog/os-command-injection/" },
  { id: 149, text: "The 2025 In-Depth Guide to OWASP Top 10 Vulnerabilities & How to Prevent Them - Jit.io", url: "https://www.jit.io/resources/security-standards/the-in-depth-guide-to-owasps-top-10-vulnerabilities" },
  { id: 150, text: "Learning SQL Injection with SQLMap in World of Haiku (Hands on Experience) - YouTube", url: "https://www.youtube.com/watch?v=YrZaBbSBTes" },
  { id: 151, text: "Analyzing the Limitations of OWASP JuiceShop as a Benchmarking Target for DAST Tools", url: "https://www.brightsec.com/blog/analyzing-the-limitations-of-owasp-juiceshop-as-a-benchmarking-target-for-dast-tools/" },
  { id: 152, text: "Web Application Security | Indusface Blog", url: "https://www.indusface.com/blog/" },
  { id: 153, text: "Top 23 Cybersecurity Websites and Blogs of 2025 - University of San Diego Online Degrees", url: "https://onlinedegrees.sandiego.edu/top-cyber-security-blogs-websites/" }
];


export default function SourcesPage() {
  return (
    <div className="container mx-auto py-8 px-4 md:px-6 lg:px-8">
      <Card className="shadow-lg rounded-lg">
        <CardHeader>
          <CardTitle className="text-3xl font-bold text-primary">Источники</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-6 text-muted-foreground">
            Список источников, использованных при подготовке материалов курса.
          </p>
          <ScrollArea className="h-[60vh] pr-4">
            <ul className="space-y-3">
              {sourcesData.map((source) => (
                <li key={source.id} className="pb-3 border-b border-border last:border-b-0">
                  <a
                    href={source.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="group flex items-start text-foreground hover:text-primary transition-colors"
                  >
                    <LinkIcon className="h-4 w-4 mr-3 mt-1 text-accent group-hover:text-primary flex-shrink-0" />
                    <span className="flex-1">{source.id}. {source.text}</span>
                  </a>
                </li>
              ))}
            </ul>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
