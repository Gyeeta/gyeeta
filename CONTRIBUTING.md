# Contributing Guidelines

Gyeeta welcomes contributions from the community. This document outlines the conventions that should be followed when making a contribution.
Please read the CODE_OF_CONDUCT.md as well.

## Contribution Process

### Reporting Bugs and Creating Issues

Bugs may be reported by filing a Github issue in the appropriate repository. Please follow the template when filing an issue and provide as much information as possible.
Before reporting a bug, we encourage you to search the existing Github issues to ensure that the bug has not already been filed.

### Code Contributions

Please create a Github issue that details the bug or feature being addressed before submitting a pull request. 
In the Github issue, contributors may discuss the viability of the solution, alternatives, and considerations.

#### Contribution Flow

**Steps to making a code contribution to any of the Gyeeta repositories will generally look like the following**

1. Fork the repository on Github.
2. Create a new branch.
3. Make your changes in organized commits.
4. Push your branch to your fork.
5. Submit a pull request to the original repository.
6. Make any changes as requested by the maintainers.
7. Once accepted by a maintainer, it will be merged into the original repository by a maintainer.

#### Contribution Checklist

When making a contribution to the repository, please ensure that the following is addressed.

1. All existing tests must pass, and new tests *may* be added for the bug/feature in question, if deemed necessary.
2. Commits are signed (see notes below).

#### Commit Messages

Commit messages should provide enough information about what has changed and why.

#### Sign your commits

The sign-off is a simple line at the end of the explanation for a commit. All commits needs to be
signed. 

You just add a line to every git commit message:

    Signed-off-by: Joe Smith <joe.smith@example.com>

Use your real name (No pseudonyms or Anonymous contributions.)

##### Configuring Commit Signing in Git

If you set your `user.name` and `user.email` git configs, you can sign your commit with `git commit -s`.

Note: If your git config information is set properly then viewing the `git log` information for your commit will look something like this:

 ```
    Author: Joe Smith <joe.smith@example.com>
    Date:   Thu Feb 2 11:41:15 2018 -0800

        Update README

        Signed-off-by: Joe Smith <joe.smith@example.com>
```

Notice the `Author` and `Signed-off-by` lines match. If they don't your PR will be rejected by the automated check.
