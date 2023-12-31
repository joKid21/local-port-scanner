<a name="readme-top"></a>




<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![LinkedIn][linkedin-shield]][linkedin-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/joKid21/local-port-scanner">
    <img src="Logo/Port-scan.png" alt="Logo" width="265" height="177.5">
  </a>

  <h3 align="center">local Port Scan</h3>

  <p align="center">
    Simple port scanner find open ports power by netcat.
    <br />
    <a href="https://github.com/joKid21/local-port-scanner"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/joKid21/local-port-scanner">View Demo</a>
    ·
    <a href="https://github.com/joKid21/local-port-scanner/issues">Report Bug</a>
    ·
    <a href="https://github.com/joKid21/local-port-scanner/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
<summary>Table of Contents</summary>
<ol>
    <li>
    <a href="#about-the-project">About The Project</a>
    <ul>
        <li><a href="#built-with">Built With</a></li>
    </ul>
    </li>
    <li>
    <a href="#getting-started">Getting Started</a>
    <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
    </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
</ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

This project is to further my knowledge in python, learn more complex way to code a project trying to cover all area's of bugs.
This tool is designed for scanning open ports on a network. It utilizes netcat to ping all IP addresses with a specified port, common ports, or the entire IP range if you have the time.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

add-ons/plugins acknowledgements

* [![Alive_Process][Alive_Process]][Alive_Process-url]
* [![Netcat][Netcat]][Netcat-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

These are the steps and prerequistes to run the program

### Prerequisites

* Python3
* Netcat
* Alive_Process

### Installation

1. go to where you downloaded Port-scan v3.py (Make sure Login.py is in the same folder)
2. open cmd
2. enter: ``` python3 Port-scan\ v3.py ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage
Default mode:
```
python3 Port-scan\ v3.py 
```
Debug mode:
```
python3 Port-scan\ v3.py -d
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

- [x] Base Logic
- [x] Check if valid ip
- [x] Run a ping command through python
- [x] Create a list of all ip's in the network then scan them
- [x] print the list in a orderly fastion where u can see the ip and which ports are open



See the [open issues](https://github.com/joKid21/local-port-scanner/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>




<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Joel Diaz - [@joeldiazkurt](https://twitter.com/joeldiazkurt) - joeldiaz2000@hotmail.com

Project Link: [https://github.com/joKid21/local-port-scanner](https://github.com/joKid21/local-port-scanner)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

Use this space to list resources you find helpful and would like to give credit to. I've included a few of my favorites to kick things off!

* [Choose an Open Source License](https://choosealicense.com)
* [w3schools](https://www.w3schools.com/python/default.asp)
* [codecademy](https://www.codecademy.com/catalog/language/python)
* [Python instatute](https://pythoninstitute.org/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/othneildrew/Best-README-Template.svg?style=for-the-badge
[contributors-url]: [![Contributors][contributors-shield]]https://github.com/joKid21/blackjack/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/joKid21/blackjack.svg?style=for-the-badge
[forks-url]: https://github.com/joKid21/local-port-scanner/forks
[stars-shield]: https://img.shields.io/github/stars/othneildrew/Best-README-Template.svg?style=for-the-badge
[stars-url]: https://github.com/joKid21/local-port-scanner/stargazers
[issues-shield]: https://img.shields.io/github/issues/othneildrew/Best-README-Template.svg?style=for-the-badge
[issues-url]: https://github.com/othneildrew/Best-README-Template/issues
[license-shield]: https://img.shields.io/github/license/othneildrew/Best-README-Template.svg?style=for-the-badge
[license-url]: https://github.com/othneildrew/Best-README-Template/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/joel-diaz-kurt/
[product-screenshot]: images/screenshot.png
[Next.js]: https://img.shields.io/badge/next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white
[Next-url]: https://nextjs.org/
[React.js]: https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB
[React-url]: https://reactjs.org/
[Vue.js]: https://img.shields.io/badge/Vue.js-35495E?style=for-the-badge&logo=vuedotjs&logoColor=4FC08D
[Vue-url]: https://vuejs.org/
[Angular.io]: https://img.shields.io/badge/Angular-DD0031?style=for-the-badge&logo=angular&logoColor=white
[Angular-url]: https://angular.io/
[Svelte.dev]: https://img.shields.io/badge/Svelte-4A4A55?style=for-the-badge&logo=svelte&logoColor=FF3E00
[Svelte-url]: https://svelte.dev/
[Laravel.com]: https://img.shields.io/badge/Laravel-FF2D20?style=for-the-badge&logo=laravel&logoColor=white
[Laravel-url]: https://laravel.com
[Bootstrap.com]: https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white
[Bootstrap-url]: https://getbootstrap.com
[JQuery.com]: https://img.shields.io/badge/jQuery-0769AD?style=for-the-badge&logo=jquery&logoColor=white
[JQuery-url]: https://jquery.com 
[Alive_Process]: https://img.shields.io/badge/Alive_Process-3.1.4-blue
[Alive_Process-url]: https://pypi.org/project/alive-progress/
[Netcat]: https://img.shields.io/badge/Netcat-7.94-blue
[Netcat-url]: https://nmap.org/download.html
