# Remote UAV Attacks & Disruption of Their Operation | MAVlink Protocol
Remote Drones Attacks &amp; Disruption of Their Operation, part of the JERICHO Project

## Introduction
There are various types of communication channels between a drone and its base station.
Our goal is to focus in a major and common communication channel, find it vulnerabilities and implement a tool that can disrupt and / or take over the UAV, using the protocols that the UAV uses for communication.

By doing it that we can also investigate and implement security and defense measures for these types of attacks.

We will focus on the **MAVLink** which is a communication protocol for UAV systems, which specifies a comprehensive set of messages exchanged between unmanned systems and ground stations (GCS). The protocol is used in major autopilot systems, mainly ArduPilot¹ and PX4.

#### **29/12/2020**

So far, we have learned some of the MAVLink security requirements, threats, and possible solutions, while focusing on the attack characteristics and UAV protection options that are more common in the protocol, with the intention of deepening the knowledge and exploring additional ways and / or improving the existing situation.


ArduPilot¹ Project provides an open source autopilot software system, which is capable of controlling almost any vehicle system imaginable including drones, and according to the developers, the software installed in over 1,000,000 vehicles world-wide, and it is a deeply tested and trusted autopilot system.
