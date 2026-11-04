local _M = {
    name = "Backup File",
    desc = "检测是否存在不安全的备份文件暴露在应用程序中，包括隐藏文件。",
    level = "medium",
    position = "uri",
    rules = {
        {
            pattern =
            [[ \.(bak[0-9]*|backup[0-9]*|old[0-9]*|orig|copy|save|tmp|temp|swp[0-9]*|sql[0-9]*|db[0-9]*|sqlite[0-9]*|log[0-9]*|1|part|crdownload|dmp|~|\.~[0-9]*~|bak~|old~|tmp~)(?![\w.;/\\-]) ]],
            name = "Common Backup and Temporary File Extensions",
            confidence = 3
        },
        {
            pattern =
            [[ (backup|bak|old|www|root|site|web|archive|copy|stored|saved|temp|temporary|dump|data|test)[0-9]*\.(tar|gz|zip|rar|7z|tgz)(?![\w.;/\\-]) ]],
            name = "Unsecure Compressed Backup Files",
            confidence = 3
        },
        {
            -- 允许 / 与 \- 但排除 . ：修复 /.git/config、/.svn/entries 漏检，同时避免 app.config.json、user.profile.png 误报；
            -- .env 单独放开（.env.production 等变体）
            pattern =
            [[ \.(?:git|htaccess|config|svn|DS_Store|bzr|cvs|hg|npmrc|yarnrc|editorconfig|eslintignore|prettierignore|dockerignore|gitignore|gitattributes|gitmodules|credentials|aws|bashrc|bash_profile|bash_logout|inputrc|nanorc|profile|tmux\.conf|vimrc|zshrc|zprofile|zlogin|zlogout|zpreztorc)(?![\w.\\-])|\.env(?!\w) ]],
            name = "Hidden Files",
            confidence = 3
        },
        {
            -- 覆盖双扩展归档（backup.sql.gz / dump.tar.gz / www.tar.gz）
            pattern =
            [[ (?:backup|bak|old|www|root|site|web|archive|copy|stored|saved|temp|temporary|dump|data|test)[\w-]*\.(?:sql|tar|txt|log|db)\.(?:gz|bz2|xz|zip|7z) ]],
            name = "Compound Archive Backup File",
            confidence = 2
        },
        {
            -- 编辑器备份后缀（index.php~ / note.~123~）
            pattern =
            [[ (?:\.[\w]{1,6}~|\.~\d*~)(?=$|[\s?#]) ]],
            name = "Editor Backup Tilde Suffix",
            confidence = 2
        },
    }
}

return _M
