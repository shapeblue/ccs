## ShapeBlue's CloudStack Container Service Plugin

Start by adding the following remote to your CloudStack repo:

    git remote add -f sbccs git@github.com:shapeblue/ccs.git

Note: run all the git subtree commands from the parent git repository's root
directory and not from plugins or plugins/ccs directory.

If you're not using cloudstack-kubernetes repo (ccs branch) you can start by adding
the plugin to plugins directory:

    git subtree add -P plugins/ccs sbccs master

Now, cd plugins/ccs and make suitable changes and commit as you would normally do.
Make changes and develop test using usualy mvn commands.

    git add -P
    git commit -s

You can push changes to ccs repository by creating a new branch and opening PRs:

    git subtree push -P plugins/ccs sbccs new-shiny-branch

Open a PR on shapeblue/ccs repository, review and merge on master. The `master`
branch is the deployable branch.

After the PR is accepted, you can pull changes:

    git subtree pull -P plugins/ccs sbccs master

Push on cloudstack-kubernetes branch suitable:

    git push origin <branch|ccs>
