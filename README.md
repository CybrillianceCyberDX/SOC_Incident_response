# SOC_Incident_response
Incident Response - End to End

Content

IR tools Collection
Adversary Emulation

    APTSimulator - Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised.
    Atomic Red Team (ART) - Small and highly portable detection tests mapped to the Mitre ATT&CK Framework.
    AutoTTP - Automated Tactics Techniques & Procedures. Re-running complex sequences manually for regression tests, product evaluations, generate data for researchers.
    Blue Team Training Toolkit (BT3) - Software for defensive security training, which will bring your network analysis training sessions, incident response drills and red team engagements to a new level.
    Caldera - Automated adversary emulation system that performs post-compromise adversarial behavior within Windows Enterprise networks. It generates plans during operation using a planning system and a pre-configured adversary model based on the Adversarial Tactics, Techniques & Common Knowledge (ATT&CK™) project.
    DumpsterFire - Modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events. Easily create custom event chains for Blue Team drills and sensor / alert mapping. Red Teams can create decoy incidents, distractions, and lures to support and scale their operations.
    Metta - Information security preparedness tool to do adversarial simulation.
    Network Flight Simulator - Lightweight utility used to generate malicious network traffic and help security teams to evaluate security controls and network visibility.
    Red Team Automation (RTA) - RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK.
    RedHunt-OS - Virtual machine for adversary emulation and threat hunting.

All in one Tools

    Belkasoft Evidence Center - The toolkit will quickly extract digital evidence from multiple sources by analyzing hard drives, drive images, memory dumps, iOS, Blackberry and Android backups, UFED, JTAG and chip-off dumps.
    CimSweep - Suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows.
    CIRTkit - CIRTKit is not just a collection of tools, but also a framework to aid in the ongoing unification of Incident Response and Forensics investigation processes.
    Cyber Triage - Cyber Triage remotely collects and analyzes endpoint data to help determine if it is compromised. It’s agentless approach and focus on ease of use and automation allows companies to respond without major infrastructure changes and without a team of forensics experts. Its results are used to decide if the system should be erased or investigated further.
    Digital Forensics Framework - Open Source computer forensics platform built on top of a dedicated Application Programming Interface (API). DFF proposes an alternative to the aging digital forensics solutions used today. Designed for simple use and automation, the DFF interface guides the user through the main steps of a digital investigation so it can be used by both professional and non-expert to quickly and easily conduct a digital investigations and perform incident response.
    Doorman - osquery fleet manager that allows remote management of osquery configurations retrieved by nodes. It takes advantage of osquery's TLS configuration, logger, and distributed read/write endpoints, to give administrators visibility across a fleet of devices with minimal overhead and intrusiveness.
    Envdb - Envdb turns your production, dev, cloud, etc environments into a database cluster you can search using osquery as the foundation. It wraps the osquery process with a (cluster) node agent that can communicate back to a central location.
    Falcon Orchestrator - Extendable Windows-based application that provides workflow automation, case management and security response functionality.
    GRR Rapid Response - Incident response framework focused on remote live forensics. It consists of a python agent (client) that is installed on target systems, and a python server infrastructure that can manage and talk to the agent.
    Kolide Fleet - State of the art host monitoring platform tailored for security experts. Leveraging Facebook's battle-tested osquery project, Kolide delivers fast answers to big questions.
    Limacharlie - Endpoint security platform composed of a collection of small projects all working together that gives you a cross-platform (Windows, OSX, Linux, Android and iOS) low-level environment for managing and pushing additional modules into memory to extend its functionality.
    Mozilla Investigator (MIG) - Platform to perform investigative surgery on remote endpoints. It enables investigators to obtain information from large numbers of systems in parallel, thus accelerating investigation of incidents and day-to-day operations security.
    MozDef - Automates the security incident handling process and facilitate the real-time activities of incident handlers.
    nightHawk - Application built for asynchronus forensic data presentation using ElasticSearch as the backend. It's designed to ingest Redline collections.
    Open Computer Forensics Architecture - Another popular distributed open-source computer forensics framework. This framework was built on Linux platform and uses postgreSQL database for storing data.
    osquery - Easily ask questions about your Linux and macOS infrastructure using a SQL-like query language; the provided incident-response pack helps you detect and respond to breaches.
    Redline - Provides host investigative capabilities to users to find signs of malicious activity through memory and file analysis, and the development of a threat assessment profile.
    The Sleuth Kit & Autopsy - Unix and Windows based tool which helps in forensic analysis of computers. It comes with various tools which helps in digital forensics. These tools help in analyzing disk images, performing in-depth analysis of file systems, and various other things.
    TheHive - Scalable 3-in-1 open source and free solution designed to make life easier for SOCs, CSIRTs, CERTs and any information security practitioner dealing with security incidents that need to be investigated and acted upon swiftly.
    X-Ways Forensics - Forensics tool for Disk cloning and imaging. It can be used to find deleted files and disk analysis.
    Zentral - Combines osquery's powerful endpoint inventory features with a flexible notification and action framework. This enables one to identify and react to changes on OS X and Linux clients.

Books

    DFIR intro - By Scott J. Roberts.
    The Practice of Network Security Monitoring: Understanding Incident Detection and Response - Richard Bejtlich's book on IR.

Communities

    augmentd - Community driven site provididing a list of searches that can be implemented in and executed with a variety of common security tools.
    Sans DFIR mailing list - Mailing list by SANS for DFIR.
    Slack DFIR channel - Slack DFIR Communitiy channel - Signup here.

Disk Image Creation Tools

    AccessData FTK Imager - Forensics tool whose main purpose is to preview recoverable data from a disk of any kind. FTK Imager can also acquire live memory and paging file on 32bit and 64bit systems.
    Bitscout - Bitscout by Vitaly Kamluk helps you build your fully-trusted customizable LiveCD/LiveUSB image to be used for remote digital forensics (or perhaps any other task of your choice). It is meant to be transparent and monitorable by the owner of the system, forensically sound, customizable and compact.
    GetData Forensic Imager - Windows based program that will acquire, convert, or verify a forensic image in one of the following common forensic file formats.
    Guymager - Free forensic imager for media acquisition on Linux.
    Magnet ACQUIRE - ACQUIRE by Magnet Forensics allows various types of disk acquisitions to be performed on Windows, Linux, and OS X as well as mobile operating systems.

Evidence Collection

    bulk_extractor - Computer forensics tool that scans a disk image, a file, or a directory of files and extracts useful information without parsing the file system or file system structures. Because of ignoring the file system structure, the program distinguishes itself in terms of speed and thoroughness.
    Cold Disk Quick Response - Streamlined list of parsers to quickly analyze a forensic image file (dd, E01, .vmdk, etc) and output nine reports.
    ir-rescue - Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.
    Live Response Collection - Automated tool that collects volatile data from Windows, OSX, and *nix based operating systems.
    Margarita Shotgun - Command line utility (that works with or without Amazon EC2 instances) to parallelize remote memory acquisition.

Incident Management

    CyberCPR - Community and commercial incident management tool with Need-to-Know built in to support GDPR compliance while handling sensitive incidents.
    Cyphon - Cyphon eliminates the headaches of incident management by streamlining a multitude of related tasks through a single platform. It receives, processes and triages events to provide an all-encompassing solution for your analytic workflow — aggregating data, bundling and prioritizing alerts, and empowering analysts to investigate and document incidents.
    Demisto - Demisto community edition(free) offers full Incident lifecycle management, Incident Closure Reports, team assignments and collaboration, and many integrations to enhance automations (like Active Directory, PagerDuty, Jira and much more).
    Fast Incident Response (FIR) - Cybersecurity incident management platform designed with agility and speed in mind. It allows for easy creation, tracking, and reporting of cybersecurity incidents and is useful for CSIRTs, CERTs and SOCs alike.
    RTIR - Request Tracker for Incident Response (RTIR) is the premier open source incident handling system targeted for computer security teams. We worked with over a dozen CERT and CSIRT teams around the world to help you handle the ever-increasing volume of incident reports. RTIR builds on all the features of Request Tracker.
    Sandia Cyber Omni Tracker (SCOT) - Incident Response collaboration and knowledge capture tool focused on flexibility and ease of use. Our goal is to add value to the incident response process without burdening the user.
    threat_note - Lightweight investigation notebook that allows security researchers the ability to register and retrieve indicators related to their research.

Linux Distributions

    The Appliance for Digital Investigation and Analysis (ADIA) - VMware-based appliance used for digital investigation and acquisition and is built entirely from public domain software. Among the tools contained in ADIA are Autopsy, the Sleuth Kit, the Digital Forensics Framework, log2timeline, Xplico, and Wireshark. Most of the system maintenance uses Webmin. It is designed for small-to-medium sized digital investigations and acquisitions. The appliance runs under Linux, Windows, and Mac OS. Both i386 (32-bit) and x86_64 (64-bit) versions are available.
    Computer Aided Investigative Environment (CAINE) - Contains numerous tools that help investigators during their analysis, including forensic evidence collection.
    CCF-VM - CyLR CDQR Forensics Virtual Machine (CCF-VM): An all-in-one solution to parsing collected data, making it easily searchable with built-in common searches, enable searching of single and multiple hosts simultaneously.
    Digital Evidence & Forensics Toolkit (DEFT) - Linux distribution made for computer forensic evidence collection. It comes bundled with the Digital Advanced Response Toolkit (DART) for Windows. A light version of DEFT, called DEFT Zero, is also available, which is focused primarily on forensically sound evidence collection.
    NST - Network Security Toolkit - Linux distribution that includes a vast collection of best-of-breed open source network security applications useful to the network security professional.
    PALADIN - Modified Linux distribution to perform various forenics task in a forensically sound manner. It comes with many open source forensics tools included.
    Security Onion - Special Linux distro aimed at network security monitoring featuring advanced analysis tools.
    SANS Investigative Forensic Toolkit (SIFT) Workstation - Demonstrates that advanced incident response capabilities and deep dive digital forensic techniques to intrusions can be accomplished using cutting-edge open-source tools that are freely available and frequently updated.

Linux Evidence Collection

    FastIR Collector Linux - FastIR for Linux collects different artefacts on live Linux and records the results in csv files.

Log Analysis Tools

    Lorg - Tool for advanced HTTPD logfile security analysis and forensics.
    Logdissect - CLI utility and Python API for analyzing log files and other data.
    StreamAlert - Serverless, real-time log data analysis framework, capable of ingesting custom data sources and triggering alerts using user-defined logic.
    SysmonSearch - SysmonSearch makes Windows event log analysis more effective and less time consuming by aggregation of event logs.

Memory Analysis Tools

    Evolve - Web interface for the Volatility Memory Forensics Framework.
    inVtero.net - Advanced memory analysis for Windows x64 with nested hypervisor support.
    KnTList - Computer memory analysis tools.
    LiME - Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, formerly called DMD.
    Memoryze - Free memory forensic software that helps incident responders find evil in live memory. Memoryze can acquire and/or analyze memory images, and on live systems, can include the paging file in its analysis.
    Memoryze for Mac - Memoryze for Mac is Memoryze but then for Macs. A lower number of features, however.
    Rekall - Open source tool (and library) for the extraction of digital artifacts from volatile memory (RAM) samples.
    Responder PRO - Responder PRO is the industry standard physical memory and automated malware analysis solution.
    Volatility - Advanced memory forensics framework.
    VolatilityBot - Automation tool for researchers cuts all the guesswork and manual tasks out of the binary extraction phase, or to help the investigator in the first steps of performing a memory analysis investigation.
    VolDiff - Malware Memory Footprint Analysis based on Volatility.
    WindowsSCOPE - Memory forensics and reverse engineering tool used for analyzing volatile memory offering the capability of analyzing the Windows kernel, drivers, DLLs, and virtual and physical memory.

Memory Imaging Tools

    Belkasoft Live RAM Capturer - Tiny free forensic tool to reliably extract the entire content of the computer’s volatile memory – even if protected by an active anti-debugging or anti-dumping system.
    Linux Memory Grabber - Script for dumping Linux memory and creating Volatility profiles.
    Magnet RAM Capture - Free imaging tool designed to capture the physical memory of a suspect’s computer. Supports recent versions of Windows.
    OSForensics - Tool to acquire live memory on 32bit and 64bit systems. A dump of an individual process’s memory space or physical memory dump can be done.

OSX Evidence Collection

    Knockknock - Displays persistent items(scripts, commands, binaries, etc.) that are set to execute automatically on OSX.
    macOS Artifact Parsing Tool (mac_apt) - Plugin based forensics framework for quick mac triage that works on live machines, disk images or individual artifact files.
    OSX Auditor - Free Mac OS X computer forensics tool.
    OSX Collector - OSX Auditor offshoot for live response.

Other Lists

    List of various Security APIs - Collective list of public JSON APIs for use in security.

Other Tools

    Cortex - Cortex allows you to analyze observables such as IP and email addresses, URLs, domain names, files or hashes one by one or in bulk mode using a Web interface. Analysts can also automate these operations using its REST API.
    Crits - Web-based tool which combines an analytic engine with a cyber threat database.
    Diffy - DFIR tool developed by Netflix's SIRT that allows an investigator to quickly scope a compromise across cloud instances (Linux instances on AWS, currently) during an incident and efficiently triaging those instances for followup actions by showing differences against a baseline.
    domfind - Python DNS crawler for finding identical domain names under different TLDs.
    Fenrir - Simple IOC scanner. It allows scanning any Linux/Unix/OSX system for IOCs in plain bash. Created by the creators of THOR and LOKI.
    Fileintel - Pull intelligence per file hash.
    HELK - Threat Hunting platform.
    Hindsight - Internet history forensics for Google Chrome/Chromium.
    Hostintel - Pull intelligence per host.
    imagemounter - Command line utility and Python package to ease the (un)mounting of forensic disk images.
    Kansa - Modular incident response framework in Powershell.
    PyaraScanner - Very simple multithreaded many-rules to many-files YARA scanning Python script for malware zoos and IR.
    rastrea2r - Allows one to scan disks and memory for IOCs using YARA on Windows, Linux and OS X.
    RaQet - Unconventional remote acquisition and triaging tool that allows triage a disk of a remote computer (client) that is restarted with a purposely built forensic operating system.
    Stalk - Collect forensic data about MySQL when problems occur.
    Scout2 - Security tool that lets Amazon Web Services administrators assess their environment's security posture.
    SearchGiant - Command-line utility to acquire forensic data from cloud services.
    Stenographer - Packet capture solution which aims to quickly spool all packets to disk, then provide simple, fast access to subsets of those packets. It stores as much history as it possible, managing disk usage, and deleting when disk limits are hit. It's ideal for capturing the traffic just before and during an incident, without the need explicit need to store all of the network traffic.
    sqhunter - Threat hunter based on osquery and Salt Open (SaltStack) that can issue ad-hoc or distributed queries without the need for osquery's tls plugin. sqhunter allows you to query open network sockets and check them against threat intelligence sources.
    traceroute-circl - Extended traceroute to support the activities of CSIRT (or CERT) operators. Usually CSIRT team have to handle incidents based on IP addresses received. Created by Computer Emergency Responce Center Luxembourg.
    X-Ray 2.0 - Windows utility (poorly maintained or no longer maintained) to submit virus samples to AV vendors.

Playbooks

    Demisto Playbooks Collection - Playbooks collection.
    IRM - Incident Response Methodologies by CERT Societe Generale.
    IR Workflow Gallery - Different generic incident response workflows, e.g. for malware outbreak, data theft, unauthorized access,... Every workflow constists of seven steps: prepare, detect, analyze, contain, eradicate, recover, post-incident handling. The workflows are online available or for download.
    PagerDuty Incident Response Documentation - Documents that describe parts of the PagerDuty Incident Response process. It provides information not only on preparing for an incident, but also what to do during and after. Source is available on GitHub.

Process Dump Tools

    Microsoft User Mode Process Dumper - Dumps any running Win32 processes memory image on the fly.
    PMDump - Tool that lets you dump the memory contents of a process to a file without stopping the process.

Sandboxing/reversing tools

    Cuckoo - Open Source Highly configurable sandboxing tool.
    Cuckoo-modified - Heavily modified Cuckoo fork developed by community.
    Cuckoo-modified-api - Python library to control a cuckoo-modified sandbox.
    Hybrid-Analysis - Free powerful online sandbox by Payload Security.
    Malwr - Free online malware analysis service and community, which is powered by the Cuckoo Sandbox.
    Mastiff - Static analysis framework that automates the process of extracting key characteristics from a number of different file formats.
    Metadefender Cloud - Free threat intelligence platform providing multiscanning, data sanitization and vulnerability assesment of files.
    Viper - Python based binary analysis and management framework, that works well with Cuckoo and YARA.
    Virustotal - Free online service that analyzes files and URLs enabling the identification of viruses, worms, trojans and other kinds of malicious content detected by antivirus engines and website scanners.
    Visualize_Logs - Open source visualization library and command line tools for logs (Cuckoo, Procmon, more to come).

Timeline tools

    Highlighter - Free Tool available from Fire/Mandiant that will depict log/text file that can highlight areas on the graphic, that corresponded to a key word or phrase. Good for time lining an infection and what was done post compromise.
    Morgue - PHP Web app by Etsy for managing postmortems.
    Plaso - a Python-based backend engine for the tool log2timeline.
    Timesketch - Open source tool for collaborative forensic timeline analysis.

Videos

    Demisto IR video resources - Video Resources for Incident Response and Forensics Tools.
    The Future of Incident Response - Presented by Bruce Schneier at OWASP AppSecUSA 2015.

Windows Evidence Collection

    AChoir - Framework/scripting tool to standardize and simplify the process of scripting live acquisition utilities for Windows.
    Binaryforay - List of free tools for win forensics (http://binaryforay.blogspot.co.il/).
    Crowd Response - Lightweight Windows console application designed to aid in the gathering of system information for incident response and security engagements. It features numerous modules and output formats.
    FastIR Collector - Tool that collects different artefacts on live Windows systems and records the results in csv files. With the analyses of these artefacts, an early compromise can be detected.
    Fast Evidence Collector Toolkit (FECT) - Light incident response toolkit to collect evidences on a suspicious Windows computer. Basically it is intended to be used by non-tech savvy people working with a journeyman Incident Handler.
    Fibratus - Tool for exploration and tracing of the Windows kernel.
    IREC - All-in-one IR Evidence Collector which captures RAM Image, $MFT, EventLogs, WMI Scripts, Registry Hives, System Restore Points and much more. It is FREE, lightning fast and easy to use.
    IOC Finder - Free tool from Mandiant for collecting host system data and reporting the presence of Indicators of Compromise (IOCs). Support for Windows only.
    Fidelis ThreatScanner - Free tool from Fidelis Cybersecurity that uses OpenIOC and YARA rules to report on the state of an endpoint. The user provides OpenIOC and YARA rules and executes the tool. ThreatScanner measures the state of the system and, when the run is complete, a report for any matching rules is generated. Windows Only.
    LOKI - Free IR scanner for scanning endpoint with yara rules and other indicators(IOCs).
    Panorama - Fast incident overview on live Windows systems.
    PowerForensics - Live disk forensics platform, using PowerShell.
    PSRecon - PSRecon gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally.
    RegRipper - Open source tool, written in Perl, for extracting/parsing information (keys, values, data) from the Registry and presenting it for analysis.
    TRIAGE-IR - IR collector for Windows.
