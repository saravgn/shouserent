## Sara Vagnarelli
## Project: House Renting

The House renting application helps to find the right structure to rent for the perfect holliday. It provides a list of structures divided by categories (studio, apartment, villa, room). In addiction, it provides a user registration and authentication system. Registered users, anyone with a Google or Facebook account, will have the ability to post, edit and delete their own trip posts.

## How to Run
Please ensure you have Python, Vagrant and VirtualBox installed. This project uses a pre-congfigured Vagrant virtual machine which has the [Flask](http://flask.pocoo.org/) server installed.

```bash
$ cd vagrant
$ vagrant up
$ vagrant ssh
```

Within the virtual machine change in to the shared directory by running

```bash
$ python catalog.py
```

### Open in a webpage

Now you can open in a webpage by going:
    http://localhost:5000