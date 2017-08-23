Syntax highlighting for Splunk's .conf files
=============

This project is public domain. Feel free to create your own branch and submit a pull request via Github or email me: colbyw at gmail dot com.

Thanks to the many contributors to this project.

![props.conf example with solarized colour scheme](http://i.imgur.com/F0rVkzt.png)

Installation Instructions
=============

You can either clone the repository somewhere on your file system and use symlinks to the corresponding directories or clone to `~/.vim/bundle` as a submodule.

Symlink instructions:
```
mkdir ~/git-projects
cd git-projects
git clone git@github.com:yorokobi/vim-splunk.git
ln -s git-projects/vim-splunk/ftdetect/splunk.vim ~/.vim/ftdetect/splunk.vim
ln -s git-projects/vim-splunk/syntax/splunk.vim ~/.vim/syntax/splunk.vim
```
Submodule/Bundle instructions:
```
cd ~/.vim/bundle
git clone git@github.com:yorokobi/vim-splunk.git
```
