+++
title = "My OSCP Journey (and tips)"
tags = ["OSCP", "exam", "TJNull", "Lain"]
date = "2025-05-25"
+++



# The Journey of 1000 Steps

- [The Journey of 1000 Steps](#the-journey-of-1000-steps)
  - [The Beginning ](#the-beginning-)
  - [Initial Plan](#initial-plan)
  - [Game Time](#game-time)
  - [Preparation](#preparation)
  - [Exam Day](#exam-day)
    - [The Plan](#the-plan)
    - [Active Directory](#active-directory)
      - [13:00 - Exam Start](#1300---exam-start)
      - [15:50 - Flag number two](#1550---flag-number-two)
      - [16:00 - Active Directory Owned](#1600---active-directory-owned)
    - [Stand Alones](#stand-alones)
      - [16:30 - Machine A - User Flag](#1630---machine-a---user-flag)
      - [18:00 - Machine A - Root/Admin Flag](#1800---machine-a---rootadmin-flag)
      - [20:00 Machine B - User flag](#2000-machine-b---user-flag)
      - [20:45 Information Gathering](#2045-information-gathering)
      - [21:30 Machine B - Root/Admin Flag](#2130-machine-b---rootadmin-flag)
      - [00:30 Machine C - User Flag](#0030-machine-c---user-flag)
      - [04:30 Machine C - Defeat](#0430-machine-c---defeat)
  - [Report Writing](#report-writing)
  - [Thoughts and Words of Advice](#thoughts-and-words-of-advice)
    - [Thoughts](#thoughts)
    - [Advice](#advice)


## <span class="rp-rose">The Beginning </span>

I originally received a LearnOne subscription in January 2022, however due to life circumstances at the time, it went largely unused. 

I lucked out, and my employer had an extra voucher laying around in May of last year. I was determined that this time, I would at the minimum take the test both times regardless of how prepared I felt.


## Initial Plan

My plan was simple, use the first two months to get through all the content, and then use the remaining time going through the challenge labs and additional boxes.

> "No plan survives first contact with the enemy"

I started out strong, but as my workload increased, the time I spent on OSCP went down drastically. When the changes from OSCP to OSCP+ were announced, I was nowhere near ready to actually pass the exam. 

I considered just yolo'ing it, and attempting the exam (I mean I get two right...), but it felt like a waste with a close to 0% chance of passing. Instead I decided to wait. And wait. And keep waiting.

I slowly made my way through the main challenge labs, (OSCP A-C). I dabbled with the other labs, but didn't get anywhere near completing them.

Out of the blue I get an email saying my LearnOne subscription will expire in 30 days.

## Game Time

I have 30 days to take my exam, but I also have a vacation planned thta will take up 16 of those 30 days. So I'm really working with two weeks. It was time to enter crunch mode.

The test had switched to assumed breach, so I did the new challenge labs that were also assumed breach. Once I was done with those, I evaluated myself on the areas where I thought I was weak and tackled boxes from Lain's list that would help.

In my opinion, OSCP level Active Directory is much more about enumeration, than it is tricky exploitation. In the challenge labs, all the intended paths were pretty simple in execution. The AD felt more like a CTF, looking for the breadcrumb that will show you the path to the next box.

I went ahead and scheduled my exam for the weekend right before my vacation. I was either going to have an extra reason to celebrate, or something else to forget. But at least it would be over.

## Preparation

Online I saw a lot of people recommending various things to take notes or copy commands. People were using Obsidian, Cherry Tree, Notion, etc. Coming from a more Linux heavy background (I use arch btw), I vastly prefer a flat text file and using vim.

I created two files, one for notes about each box. This file had sections for credentials found, scan results, and a general notes section. Having a system in place to keep track of all the information as you find it, is tremendously helpful. A piece of information you find at the start may not be immediately useful, but could end up being the key piece to a privesc.

The second file, was my commands/notes file. This was broken into sections for Scanning, Initial Enumeration, PrivEsc Vectors, AD Enumeration. At the top of the file, I had some highlights for things I missed in the challenge labs, that way every time I looked at the file, I was reminded of those things. I did not want to miss something I had missed before, like trying different casing for credentials. 

The majority of the file, would be commands, with variables in place of the options. An example follows.

```bash
nxc smb $target_ip --shares
echo "test"
ftp anonymous@$target_ip

```

<span class="rp-rose">Rose text</span>

<span class="rp-foam">Foam text</span>

<span class="rp-gold">Gold text</span>


I also made a few scripts to help me save time, and mental load during the exam. I think the most useful thing, is to practice with all the tools you intend to use. You don't want to waste precious mental resources on how to run a command during the exam.

For example, I made a simple script named [tools-upload](https://github.com/working-git/random-tools/blob/main/tool-upload.py). It *shocker* is a wrapper to upload tools to the target box.

<!-- Put screenshot of tools-upload here -->

Now instead of trying to type out an IWR command, I can just copy the line for the file I want, and paste it on the target machine.

I'd also recommend having commands ready for your proofs of the machines. That way you just copy and paste the applicable line to the machine and take your screenshot. Again, don't want to waste mental capacity worrying if you have the correct information in your screenshot.

## Exam Day

### The Plan

My plan going in, was to start with AD, and then move to the stand-alones. It's impossible to pass without AD, so I figured it was better to get it out of the way.


### Active Directory

I scheduled my exam to start close to when I would normally start work. I've seen advice on different start times, I would say to stick to what you know. If you work 4pm to 12am, you should heavily consider starting your exam at 4pm. 

Before my exam started, I made a snapshot of my VM, just in case anything went wrong during the exam.

Check-in went smoothly, and my heart started to beat faster and faster as the thoughts of failure raced through my mind. 


#### 13:00 - Exam Start

I start on the AD with some enumeration, and manage to get the first flag in 40 minutes. Off to a great start, this helped ease some of the nerves. 

#### 15:50 - Flag number two

Able to pivot and get a shell on the second box in the set. I ran into a roadblock, and spent an unfortunate amount of time troubleshooting an issue. (Have a troubleshooting process) I figured out my issue, and got my second flag XX minutes in. Only the DC remained, and I already saw my path to it.

#### 16:00 - Active Directory Owned

After I got through the hurdles on the second box, I was almost immediately on the DC. Like I said earlier, sometimes a piece of information you find isn't immediately actionable, but could be the key later.

### Stand Alones

Once I finished up with the AD set, I took a small break to eat and reset mentally. 

I came back, sat down, and put on "Severance -- Music to Refine To". I started my scans of all three machines, hoping for an easy win. 

#### 16:30 - Machine A - User Flag

Much to my surprise, one of the machines has some low hanging fruit that gives me a shell. One more flag, and now I'm two flags away from hitting that magical number.

#### 18:00 - Machine A - Root/Admin Flag

During my enumeration I noticed something odd, I was sure it was the intended privesc, but I had no idea how to use it. After a literal *hour* of googling, I stumbled upon an article detailing how to abuse what I saw. With this knowledge in hand, it was relatively simple to privesc, and I had another flag in my belt. 

> One more flag, one more.

The only thing in my head was getting one more flag. I took one more break, feeling confident that I was going to pass.

I felt like I was banging my head against a wall. I thought I *knew* the path to user for both Machine B and C, but I wasn't having any luck. I tried variations of the techniques I was using, and finally...

#### 20:00 Machine B - User flag

After a lot of floundering, I finally manage to get a foothold on Machine B. And with that foothold, my final flag needed to pass. I let out a sigh and I felt all my tension leave my body. I took a break to try and give my brain a rest.

#### 20:45 Information Gathering

While everything was fresh, I went through the steps to exploit the boxes I had completed so far. I made sure to capture screenshots and jot down notes along the way. Getting 70 points doesn't matter if your report isn't deemed to be enough, so I focused on getting everything I would need together. I thought about calling it quits, but I told myself I'd go for one more hour.


#### 21:30 Machine B - Root/Admin Flag

I run through more enumeration and finally stumble upon the privesc. Right before my self-imposed cutoff time I got another flag. Stopping at 70 was acceptable, stopping at 80? Might as well keep going.

#### 00:30 Machine C - User Flag

I *knew* the path to getting a user foothold, but implementing it was very difficult for me. After many hours of trying, failing, trying, failing, and trying some more. I finally got the initial foothold. I screamed so loud, I wouldn't be surprised if I jump scared the proctors. I made it to 90 points, the mythical triple digits was in reach. I could do this.


#### 04:30 Machine C - Defeat

Turns out... I couldn't do it.

After hours and hours of enumeration, I was lost for the final privesc. It had been 12 hours since I started the exam, so I decided to call it quits. I had work the next day, and a report to write. I needed all the extra time I could get.

I took my last screenshots, verified that my proofs had all the correct information. And finally I checked out with the proctors.

## Report Writing

OffSec provides a word doc template to generate the report, but I wanted to try a solution that could be helpful going forward. I decided to host SysReptor on an Ubuntu VM, and I'd easily recommend it for anyone goind down this path. It comes with some helpful command line utilities, like being able to convert your nmap output to something more report friendly.

It took me about four hours, to draft the report and verify I wasn't missing any important (read: required) information.

## Thoughts and Words of Advice


### Thoughts

Do I recommend taking OSCP? 

Yes*

I think the material and the labs are pretty valuable. However, this comes at a pretty steep asking price. If your employer is able to purchase a voucher, or you *need* it for a job, I can recommend it. 

If it's coming out of your own pocket, that's a lot harder. Nothing in the course material can't be found elsewhere. For some of the topics, I even prefer other learning resources. However, I will say the Challenge Labs provided, and the exam itself, feels less like a CTF than other options. 

### Advice

The single most helpful piece of advice I read during my journey was simple. If (read: when) you get stuck and need to look at a write-up or get a hint. Add whatever you got stuck on to your notes. I prefer brevity and conciseness, so at the top of my command reference file I had a bunch of notes that were useful to me.

<!-- Screen shot of command file -->

