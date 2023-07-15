---
title : "CRTE Exam Review"
author: Bhaskar Pal
date: 2023-07-15 07:23:00 +0530
categories: [Red-Teaming-Exams,CRTE-Review]
tags: [active-directory,CRTE-exam]
---

![crte-header](https://github.com/0xStarlight/0xStarlight.github.io/assets/59029171/830560ee-4dae-48bc-ab60-28dedfb8745e)


# <span style="color:lightblue">Introduction</span>

I am thrilled to announce that I have successfully passed the CRTE (Certified Red Team Expert) exam from Altered Security, and I am excited to share my journey and experience with all of you. This certification marks a significant milestone in my career as a cybersecurity professional, further building upon my earlier achievements of attaining the CRTP (Certified Red Team Professional) and the CRTO (Certified Red Team Operator) certifications.

Throughout my preparation and examination process, I encountered numerous challenges, gained invaluable insights, and developed a deeper understanding of the red teaming discipline. This blog aims to provide a comprehensive account of my experiences, shedding light on the preparation strategies, lab reviews, and the exam itself. Moreover, I will share tips and techniques that I found helpful in conquering the CRTE exam, offering guidance to those who aspire to follow a similar path.

# <span style="color:lightblue">Preperation</span>

![exam-prep](https://github.com/0xStarlight/0xStarlight.github.io/assets/59029171/c3c0326f-0e45-4083-8b3d-8467f6a28b63)


When preparing for the CRTE exam, it's essential to establish a strong foundation in red teaming concepts and techniques. Red teaming involves simulating real-world attacks to identify vulnerabilities within an organization's security infrastructure. To ensure a smoother transition into CRTE, I recommend completing the CRTP (Certified Red Team Professional) certification first.

The CRTP certification covers a wide range of essential topics that serve as the building blocks for CRTE. It delves into areas such as Active Directory (AD) enumeration, trust mapping, domain privilege escalation, Kerberos-based attacks, SQL server trusts, defences, and bypasses of defences. By acquiring a solid understanding of these fundamental concepts through the CRTP, you will be better equipped to tackle the more advanced content in CRTE.

Additionally, I had the opportunity to complete the CRTO (Certified Red Team Operator) certification, which focuses on conducting red team exams using the C2 framework "Cobalt Strike". While I wouldn't consider the CRTO a prerequisite for CRTE, it gave me valuable hands-on experience and a deeper understanding of red teaming methodologies. The CRTO exam-based approach, combined with using Cobalt Strike, enhanced my practical skills and complemented the theoretical knowledge gained from the CRTP.

Engaging in practical exercises related to Active Directory was beneficial for extra preparation.

+ HackTheBox : Easy-Medium Level Boxes
+ HackTheBox ProLabs : Rastalabs or Offshore
+ TCM Security : PEH Course

# <span style="color:lightblue">CRTE Lab</span>

For the lab portion of the CRTE certification, you can choose between "On Demand" and "Online Bootcamp."

## <span style="color:lightgreen">Bootcamp</span>

The "Bootcamp" option, is a 4-day workshop conducted weekly, with each session lasting approximately 3.5 hours. The course instructor covers the relevant concepts in these live sessions and demonstrates various objectives. The "Bootcamp" option is particularly beneficial for those who prefer a more guided approach and would like additional support throughout the lab exercises. However, having already solved Hack The Box Pro Labs, I felt confident that I could tackle the labs independently. Thus, I chose the "On Demand" option to proceed with my CRTE lab experience.


## <span style="color:lightgreen">On Demand</span>

The "On Demand" option grants you access to the lab environment for your choice, ranging from 30 to 90 days. Priced at $299 for the 30-day access, this option includes all the necessary tools and a lab PDF that is solved using PowerShell. Additionally, the lab is solved using the C2 framework "Covalent." In the "On Demand" option, students are expected to work independently on the lab challenges. However, if you encounter any difficulties, you can seek assistance by contacting the support team via email or by engaging with fellow students in the dedicated Discord group.

![LabDiagram](https://github.com/0xStarlight/0xStarlight.github.io/assets/59029171/3225e553-99b2-4216-9004-5d4bb784f2c2)


I opted for the "On Demand" option and immediately began my lab journey after purchasing it on June 29th. The lab consists of 22 machines distributed across 8 forests, encompassing advanced attack scenarios. These scenarios cover various topics, including abuse of Kerberos Delegation, PAM Trust Abuse, LAPS, Dimond Tickets, MSSQL Abuse, Certificate Services, Shadow Credentials, and more. Additionally, the lab contains a total of 60 flags to discover. 

Remarkably, I completed all the flags within 48 hours, spanning 4 days. To ensure I captured all the vital details, I diligently took comprehensive notes using Obsidian, documenting the attack techniques I utilized and the corresponding commands. In the end, you also have the option to tweet about the lab completion.

![crte_flags_pwn](https://github.com/0xStarlight/0xStarlight.github.io/assets/59029171/c0509b4e-aa6b-43c6-91a9-5c0dc9cca074)


# <span style="color:lightblue">Exam Experience</span>

## <span style="color:lightgreen">Exam Setup</span>
The CRTE exam offers the flexibility of an on-demand start, eliminating the need for advanced scheduling. The exam setup process typically takes around 10-15 minutes. Upon commencement, you are provided an additional hour of lab access, extending the total exam lab time to 48 hours plus 1 hour. Following the completion of the exam, you are granted an extra 48 hours to prepare and submit a comprehensive report. This report should include meticulous details such as screenshots and tool references for each attack that exploits specific machines.

To successfully pass the CRTE exam, you must demonstrate your proficiency by solving at least 4 out of 5 machines. Alongside your successful exploitation, delivering a high-quality report encompassing key elements such as thorough enumeration, step-by-step exploitation methodology, post-exploitation activities, and suggested mitigations is crucial.

By adhering to these requirements and presenting a well-documented report, you can effectively showcase your understanding of the exam objectives and secure a successful outcome in the CRTE certification exam.

## <span style="color:lightgreen">Exam Journey</span>

During my CRTE exam journey, I commenced the examination on July 6th around 12:30 PM. The exam would end in 48 hours and would have an extra 48 hours to submit the reort.

![exam-start-img](https://github.com/0xStarlight/0xStarlight.github.io/assets/59029171/ee3bfeb4-2ec9-4ec0-a40a-57ad8c9701e7)


The initial compromise of the first machine proved to be relatively straightforward, requiring adherence to the basic attack methodology that eventually led me to discover something intriguing. I could attain a reverse shell on the target system by leveraging this discovery.

However, the second machine presented a more challenging task, demanding additional research beyond what was covered in the course materials. Diligent exploration and in-depth investigation on various abuse techniques were necessary to overcome this obstacle successfully.

Fortunately, the third machine posed fewer difficulties, with the attack path becoming quite apparent during the enumeration process. This clarity facilitated a relatively swift compromise.

On the other hand, the fourth machine initially posed a minor setback as I mistakenly assumed a particular attack vector without conducting a thorough enumeration. Once I corrected this oversight and performed comprehensive enumeration, the correct attack path became evident, leading to a successful compromise.

Lastly, the fifth machine followed a similar pattern of relative ease, with the attack path visible, making it more straightforward to exploit and compromise.

I completed the CRTE exam in just 17 hours and submitted the accompanying report within 24 hours. 

![exam-end](https://github.com/0xStarlight/0xStarlight.github.io/assets/59029171/b72847fe-a1cc-44b7-9522-2f6c2d4fa63c)


Although I admittedly spent some time exploring non-essential aspects, those who approach the exam more directly can reasonably expect to finish within 6 to 9 hours. By staying focused and minimizing distractions, candidates can optimize their exam experience and achieve efficient results.

## <span style="color:lightgreen">Exam Review</span>

![exam-exp](https://github.com/0xStarlight/0xStarlight.github.io/assets/59029171/b7eb8d7c-5e9f-4b89-ada0-862ce2a73636)


Reflecting on my exam experience, I can't help but recall a popular meme that perfectly encapsulates it all. While the CRTE course delved into numerous advanced attack vectors, it was interesting that those specific vectors weren't prominently featured in the exam. It's important to emphasize that this doesn't necessarily imply that the exam was more challenging or straightforward. Instead, what truly mattered was a comprehensive understanding of the methodology and a strategic approach when dealing with an Active Directory environment.

A solid grasp of the methodology and navigating an Active Directory environment proved crucial during the exam. By applying this knowledge effectively, the exam unfolded smoothly. Moreover, the exam's success relied on conducting proper research, delving into the necessary techniques, and employing sound practices. Armed with these preparations, compromising each machine became an achievable feat.

# <span style="color:lightblue">Exam Tips</span>

1. Develop a Methodology: Build a proper methodology for attacking an AD environment, encompassing the enumeration, exploitation, and post-exploitation phases. It is crucial to mention the mitigations for each step exploited in your report, demonstrating a comprehensive understanding of defensive measures.

2. Focus on Enumeration: Prioritize thorough enumeration as it is the key to uncovering crucial information about the target environment. Invest ample time in gathering details about users, groups, privileges, and potential vulnerabilities.

3. Utilize BloodHound: Familiarize yourself with the powerful tool BloodHound, which provides valuable insights into AD environments. If needed, employ manual enumeration using PowerShell to gather additional information.

4. Maintain a List of Attacks and Techniques: Keep a comprehensive list of enumeration techniques and potential attacks. If BloodHound or initial enumeration doesn't yield desired results, refer to your list to explore alternative attack paths.

5. Correlate User and Credential Information: Take note of all users and credentials you discover during the exam. Correlating this information may uncover valuable hints or clues for further exploitation and privilege escalation.

6. Document Mitigations: Pay attention to potential mitigations for the vulnerabilities and attack vectors you encounter. Include these mitigations in your report to showcase your understanding of defensive measures and provide a thorough analysis.

7. Take Breaks and Manage Stress: Remember to take regular breaks, eat well, and rest during the exam. Managing stress levels and maintaining a clear mindset will help enhance your focus and overall performance.

Feel free to check out my cheat sheet for CRTE exam on my github [CRTE-NOTES](https://github.com/0xStarlight/CRTE-Notes/). This cheat sheet includes additional insights and strategies to help you prepare effectively for the exam.


# <span style="color:lightblue">Conclusion</span>

In conclusion, undertaking the CRTE lab and exam proved to be a rewarding experience. The lab environment provided an excellent platform for practical application, allowing me to exercise the attack vectors covered in the course and explore various chained attacks. The support team demonstrated exceptional responsiveness throughout the lab, promptly addressing any lab-related issues and assisting whenever I encountered challenges.

Transitioning to the exam phase, the difficulty level was relatively moderate. I could successfully navigate the exam with a diligent research approach and well-established methodology. The exam tested not only my technical knowledge but also my ability to apply that knowledge in a methodical manner.

After eagerly awaiting the results, I received the outcome via email after a week, and to my delight, I learned that I had passed the exam! 

![Bhaskarpal_CRTE](https://github.com/0xStarlight/0xStarlight.github.io/assets/59029171/95dc4a8a-84f3-400e-8268-54b4f4b9e9ba)


If you find my articles interesting, you can buy me a coffee 

<a href="https://www.buymeacoffee.com/0xStarlight"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me an OSEP?&emoji=&slug=0xStarlight&button_colour=b86e19&font_colour=ffffff&font_family=Poppins&outline_colour=ffffff&coffee_colour=FFDD00" /></a>
