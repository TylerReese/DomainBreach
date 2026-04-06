<#
.SYNOPSIS
    Builds a deliberately vulnerable Active Directory lab environment for red-team and CTF training.

.DESCRIPTION
    DomainBreach automates the creation of realistic AD attack paths by populating a domain with
    randomised users and groups, then intentionally misconfiguring it with 19 vulnerability modules.

    Modes of operation:
      -Setup       Install the AD DS role and promote this machine to a domain controller.
      -Populate    Create users and apply all 19 vulnerability modules in one shot.
      -Rollback    Undo every change recorded in a state file.
      -Check       Run prerequisite checks only (admin, DC, AD DS role, SMBv1).
      -Menu        Launch the interactive menu (default when no parameters are supplied).

    All changes are logged to a JSON state file so the environment can be cleanly rolled back.
    Run from an elevated PowerShell session on a domain controller.
    Requires the ActiveDirectory module (RSAT or the AD DS role).

.PARAMETER DomainName
    Fully-qualified DNS name of the target domain (e.g. corp.local).
    Required by -Populate. When omitted, auto-discovery is attempted via Get-ADDomain and the
    USERDNSDOMAIN environment variable before prompting.

.PARAMETER UsersLimit
    Number of randomised AD user accounts to create during -Populate. Defaults to 100.

.PARAMETER Rollback
    Revert every change recorded in the state file specified by -StateFile.
    Removes users, groups, service accounts, ACL entries, and restores registry/policy settings
    to the values captured before DomainBreach ran.

.PARAMETER Setup
    Install the AD DS Windows role and promote this machine to a new-forest domain controller.
    Combines Invoke-DomainBreachRoleInstall and Invoke-DomainBreachDCPromoNewForest.

.PARAMETER Populate
    Run all 19 vulnerability modules against the target domain. Creates users, groups, and
    service accounts, then applies misconfigurations. Saves a state file for later rollback.

.PARAMETER Check
    Execute prerequisite checks only: admin privileges, domain-controller status, AD DS role
    installation, and SMBv1 driver availability. Does not make any changes.

.PARAMETER Menu
    Launch the interactive menu. This is the default mode when the script is run without any
    recognised parameters or domain name.

.PARAMETER StateFile
    Path to the JSON state file used by -Rollback (required) or written by -Populate (optional;
    defaults to domainbreach_<domain>_<timestamp>.json in the current directory).

.PARAMETER SkipSMBv1Reboot
    Suppress the reboot prompt that appears when the FS-SMB1 Windows feature is installed
    during a run. The reboot is still required for SMBv1 to become active, but the script
    will continue without waiting.

.PARAMETER VerboseMode
    Enable verbose and debug output. When set:
      - All [*] progress messages from every module are printed in cyan.
      - Silent error catch blocks print a yellow [DBG] line showing the exact exception,
        making it easy to diagnose which AD operations are failing and why.
    Can also be toggled at any time from the interactive menu with [V].

.PARAMETER TargetOU
    Name of the Organizational Unit under the domain root where all created objects (users,
    groups, service accounts, and computer accounts) will be placed. Defaults to "DomainBreach".
    The OU is created automatically if it does not exist. Pass an empty string ("") to skip OU
    creation and let AD place objects in their default containers.
    On rollback, the OU is removed automatically if it was created by DomainBreach.

.EXAMPLE
    .\domainbreach.ps1 -Check

    Run prerequisite checks without making any changes.

.EXAMPLE
    .\domainbreach.ps1 -Populate -DomainName corp.local

    Populate corp.local with 100 users and all 19 vulnerability modules. Objects are placed
    in OU=DomainBreach,DC=corp,DC=local (created automatically).

.EXAMPLE
    .\domainbreach.ps1 -Populate -DomainName corp.local -TargetOU "LabUsers"

    Populate using a custom OU name. Objects go into OU=LabUsers,DC=corp,DC=local.

.EXAMPLE
    .\domainbreach.ps1 -Populate -DomainName corp.local -UsersLimit 50 -VerboseMode

    Populate with 50 users and print detailed step-by-step debug output for every operation,
    including errors from operations that would normally fail silently.

.EXAMPLE
    .\domainbreach.ps1 -Rollback -StateFile .\domainbreach_corp.local_20250101_120000.json

    Roll back all changes recorded in the specified state file, including removal of the
    DomainBreach OU if it was created during that run.

.EXAMPLE
    .\domainbreach.ps1 -Menu

    Open the interactive menu. Press [V] inside the menu to toggle verbose/debug output.
    Option [5] prompts for OU name before running all modules.

.EXAMPLE
    Get-Help .\domainbreach.ps1 -Full

    Show this full help page including all parameters and examples.

.NOTES
    Author  : Tyler Reese (@tyler_reese)
    Purpose : Lab / CTF environment setup - DO NOT run on production domains.
#>
[CmdletBinding()]
Param(
    [string]$DomainName  = "",
    [int]$UsersLimit     = 100,
    [switch]$Rollback,
    [switch]$Setup,
    [switch]$Populate,
    [switch]$Check,
    [switch]$Menu,
    [string]$StateFile   = "",
    [switch]$SkipSMBv1Reboot,
    [switch]$VerboseMode,
    [string]$TargetOU    = "DomainBreach"
)
#Base Lists 
$Global:HumansNames = @('Linda', 'James', 'Michael', 'Robert', 'John', 'David', 'Mary', 'William', 'Jennifer', 'Lisa', 'Christopher', 'Richard', 'Mark', 'Patricia', 'Jessica', 'Jason', 'Ashley', 'Deborah', 'Debra', 'Matthew', 'Barbara', 'Thomas', 'Susan', 'Joshua', 'Shirley', 'Amanda', 'Charles', 'Karen', 'Dorothy', 'Cynthia', 'Gary', 'Daniel', 'Steven', 'Betty', 'Brittany', 'Donna', 'Brian', 'Andrew', 'Helen', 'Jacob', 'Justin', 'Larry', 'Ronald', 'Sandra', 'Michelle', 'Carol', 'Kimberly', 'Melissa', 'Jeffrey', 'Joseph', 'Nancy', 'Amy', 'Scott', 'Timothy', 'Kevin', 'Tyler', 'Donald', 'Ryan', 'Brandon', 'Nicholas', 'Sharon', 'Sarah', 'Margaret', 'Kenneth', 'George', 'Pamela', 'Paul', 'Kathleen', 'Emily', 'Ruth', 'Austin', 'Angela', 'Samantha', 'Zachary', 'Judith', 'Anthony', 'Stephanie', 'Dennis', 'Jonathan', 'Brenda', 'Heather', 'Cheryl', 'Adam', 'Kathy', 'Lori', 'Eric', 'Diane', 'Hannah', 'Stephen', 'Nicole', 'Isabella', 'Emma', 'Kyle', 'Sophia', 'Ethan', 'Madison', 'Gregory', 'Jeremy', 'Taylor', 'Tammy', 'Edward', 'Lauren', 'Joan', 'Judy', 'Elizabeth', 'Carolyn', 'Liam', 'Alexander', 'Cindy', 'Megan', 'Cody', 'Olivia', 'Alexis', 'Noah', 'Debbie', 'Mason', 'Virginia', 'Crystal', 'Laura', 'Teresa', 'Jerry', 'Kayla', 'Janet', 'Tracy', 'Tiffany', 'Kelly', 'Julie', 'Mildred', 'Ava', 'Christine', 'Jayden', 'Frank', 'Danielle', 'Amber', 'Rebecca', 'Douglas', 'Joyce', 'Christina', 'Doris', 'Randy', 'Dylan', 'Rachel', 'Chelsea', 'Jordan', 'Frances', 'Christian', 'Aiden', 'Janice', 'Abigail', 'Benjamin', 'Dawn', 'Anna', 'Robin', 'Terry', 'Courtney', 'Denise', 'Todd', 'Logan', 'Aaron', 'Mia', 'Erin', 'Samuel', 'Tina', 'Patrick', 'Bruce', 'Nathan', 'Evelyn', 'Harold', 'Oliver', 'Alyssa', 'Elijah', 'Shannon', 'Chad', 'Ricky', 'Walter', 'Charlotte', 'Roger', 'Gabriel', 'Lucas', 'Victoria', 'Amelia', 'Jamie', 'Brianna', 'Raymond', 'Jose', 'Dolores', 'Shawn', 'Jack', 'Grace', 'Cameron', 'Marie', 'Gloria', 'Jackson', 'Hunter', 'Jean', 'Kim', 'Keith', 'Jasmine', 'Catherine', 'Mike', 'Sean', 'Jacqueline', 'Theresa', 'Alice', 'Addison', 'Chloe', 'Marilyn', 'Gavin', 'Kelsey', 'Andrea', 'Caleb', 'Katherine', 'Angel', 'Peter', 'Travis', 'Gerald', 'April', 'Henry', 'Sara', 'Florence', 'Beverly', 'Wendy', 'Michele', 'Marjorie', 'Rodney', 'Steve', 'Natalie', 'Rhonda', 'Cathy', 'Morgan', 'Harper', 'Carter', 'Craig', 'Alexandra', 'Laurie', 'Martha', 'Irene', 'Arthur', 'Luke', 'Lois', 'Landon', 'Isaiah', 'Jesse', 'Dustin', 'Lawrence', 'Owen', 'Evan', 'Sebastian', 'Isaac', 'Sydney', 'Shelby', 'Bonnie', 'Wayne', 'Albert', 'Maria', 'Paula', 'Peggy', 'Aidan', 'Lillian', 'Connor', 'Connie', 'Erica', 'Jane', 'Harry', 'Gail', 'Ella', 'Destiny', 'Rose', 'Eugene', 'Kristin', 'Wyatt', 'Sofia', 'Avery', 'Billy', 'Whitney', 'Kristen', 'Jeff', 'Diana', 'Jeffery', 'Sherry', 'Phyllis', 'Louise', 'Stacy', 'Brayden', 'Danny', 'Haley', 'Ann', 'Alan', 'Levi', 'Lindsey', 'Mateo', 'Ralph', 'Julia', 'Gladys', 'Hailey', 'Terri', 'Sheila', 'Norma', 'Kaitlyn', 'Bryan', 'Edna', 'Grayson', 'Josephine', 'Carrie', 'Lindsay', 'Theodore', 'Kathryn', 'Eleanor', 'Dale', 'Troy', 'Julian', 'Carole', 'Ruby', 'Diego', 'Derek', 'Katie', 'Carl', 'Tony', 'Darlene', 'Juan', 'Vicki', 'Lincoln', 'Lily', 'Mila', 'Allison', 'Jaxon', 'Camila', 'Ethel', 'Eli', 'Herbert', 'Aubrey', 'Luis', 'Jo', 'Joe', 'Corey', 'Willie', 'Lucille', 'Adrian', 'Jimmy', 'Jill', 'Edith', 'Thelma', 'Jaime', 'Brittney', 'Gianna', 'Alicia', 'Warren', 'Luna', 'Bobby', 'Lynn', 'Jeremiah', 'Howard', 'Scarlett', 'Wanda', 'Alex', 'Hazel', 'Asher', 'Vanessa', 'Roy', 'Stacey', 'Leo', 'Russell', 'Annie', 'Zoey', 'Jared', 'Johnny', 'Aria', 'Chase', 'Glenn', 'Clarence', 'Valerie', 'Louis', 'Caitlin', 'Tonya', 'Tara', 'Pauline', 'Kaylee', 'Bradley', 'Chris', 'Brooklyn', 'Randall', 'Riley', 'Annette', 'Savannah', 'Elaine', 'Cassandra', 'Josiah', 'Vickie', 'Mackenzie', 'Dana', 'Tim', 'Brandy', 'Suzanne', 'Carlos', 'Nathaniel', 'Nevaeh', 'Hudson', 'Leah', 'Earl', 'Ezra', 'Brooke', 'Seth', 'Penelope', 'Beth', 'Ian', 'Rita', 'June', 'Trevor', 'Monica', 'Barry', 'Dakota', 'Esther', 'Xavier', 'Fred', 'Layla', 'Colton', 'Hayden', 'Zoe', 'Cory', 'Stanley', 'Jenna', 'Jace', 'Holly', 'Gina', 'Francis', 'Dominic', 'Misty', 'Gertrude', 'Brody', 'Melanie', 'Philip', 'Jaden', 'Alfred', 'Marissa', 'Tracey', 'Ayden', 'Devin', 'Gabrielle', 'Bernice', 'Gabriella', 'Vincent', 'Alexa', 'Ronnie', 'Shaun', 'Leslie', 'Maverick', 'Martin', 'Joanne', 'Nora', 'Marion', 'Blake', 'Phillip', 'Cole', 'Renee', 'Tanya', 'Marcus', 'Lorraine', 'Miranda', 'Katelyn', 'Beatrice', 'Makayla', 'Ellen', 'Darren', 'Krystal', 'Elias', 'Bentley', 'Madeline', 'Garrett', 'Sierra', 'Carla', 'Sabrina', 'Angelina', 'Anita', 'Clara', 'Paige', 'Anne', 'Nolan', 'Parker', 'Shane', 'Ernest', 'Jim', 'Tristan', 'Leonard', 'Easton', 'Trinity', 'Audrey', 'Faith', 'Norman', 'Marsha', 'Curtis', 'Kristina', 'Ellie', 'Kylie', 'Brandi', 'Aaliyah', 'Ariana', 'Rick', 'Sherri', 'Geraldine', 'Mariah', 'Ashton', 'Ariel', 'Khloe', 'Juanita', 'Greg', 'Violet', 'Jay', 'Mitchell', 'Franklin', 'Kristy', 'Marlene', 'Peyton', 'Sue', 'Marcia', 'Jocelyn', 'Agnes', 'Skylar', 'Arianna', 'Cooper', 'Sally', 'Miles', 'Carson', 'Claire', 'Bailey', 'Elsie', 'Aurora', 'Allen', 'Christy', 'Stella', 'Bella', 'Darryl', 'Penny', 'Colin', 'Paisley', 'Antonio', 'Dillon', 'Jaxson', 'Tom', 'Caden', 'Bertha', 'Latoya', 'Maya', 'Santiago', 'Alexandria', 'Caroline', 'Ezekiel', 'Marc', 'Regina', 'Briana', 'Frederick', 'Brady', 'Nova', 'Dean', 'Erik', 'Calvin', 'Jon', 'Miguel', 'Roman', 'Cheyenne', 'Sadie', 'Greyson', 'Lynda', 'Micheal', 'Patsy', 'Luca', 'Darrell', 'Emilia', 'Everly', 'Becky', 'Kaden', 'Brett', 'Sophie', 'Kayden', 'Heidi', 'Tamara', 'Tanner', 'Breanna', 'Bill', 'Meghan', 'Jameson', 'Bryson', 'Molly', 'Axel', 'Joel', 'Spencer', 'Lucy', 'Maureen', 'Tommy', 'Willow', 'Erika', 'Madelyn', 'Dalton', 'Eva', 'Alejandro', 'Jase', 'Colleen', 'Rosemary', 'Isla', 'Kennedy', 'Pearl', 'Bernard', 'Joann', 'Jake', 'Serenity', 'Eddie', 'Aubree', 'Marvin', 'Ida', 'Victor', 'Constance', 'Dianne', 'Leonardo', 'Veronica', 'Elmer', 'Sylvia', 'Jeanne', 'Annabelle', 'Genesis', 'Deanna', 'Viola', 'Bryce', 'Wesley', 'Roberta', 'Brent', 'Sawyer', 'Jada', 'Jackie', 'Eileen', 'Melvin', 'Melinda', 'Glenda', 'Autumn', 'Valeria', 'Marian', 'Jodi', 'Wilma', 'Lance', 'Ryder', 'Delores', 'Derrick', 'Piper', 'Sheryl', 'Casey', 'Natasha', 'Vivian', 'Bessie', 'Adeline', 'Don', 'Isabelle', 'Shelly', 'Myrtle', 'Everett', 'Naomi', 'Kinsley', 'Nellie', 'Eliana', 'Malik', 'Kiara', 'Isabel', 'Brendan', 'Damian', 'Declan', 'Max', 'Elena', 'Leroy', 'Vera', 'Arlene', 'Loretta', 'Camden', 'Colby', 'Mikayla', 'Traci', 'Brooks', 'Bianca', 'Kendra', 'Edwin', 'Selena', 'Kaleb', 'Kai', 'Ivy', 'Preston', 'Candice', 'Valentina', 'Rickey', 'Weston', 'Yolanda', 'Micah', 'Rosalie', 'Lloyd', 'Maxwell', 'Mindy', 'Dan', 'Chester', 'Yvonne', 'Lee', 'Mabel', 'Pam', 'Harrison', 'Maxine', 'Alma', 'Quinn', 'Sandy', 'Payton', 'Lydia', 'Jade', 'Kay', 'Floyd', 'Kaitlin', 'Oscar', 'Silas', 'Sheena', 'Cora', 'Jessie', 'Natalia', 'Bennett', 'Waylon', 'Emmett', 'Charlene', 'Kristine', 'Gwendolyn', 'Jorge', 'Jalen', 'Dwayne', 'Gracie', 'Tricia', 'Ivan', 'London', 'Giovanni', 'Clifford', 'Alec', 'Eduardo', 'Mya', 'Ray', 'Jayla', 'Angelica', 'Michaela', 'Katrina', 'Cassidy', 'Delilah', 'Claudia', 'Gabriela', 'Collin', 'Woodrow', 'Braxton', 'Kingston', 'Brantley', 'Leona', 'Kelli', 'Joanna', 'Mallory', 'Beau', 'Grant', 'Dave', 'Genevieve', 'Dominique', 'Bethany', 'Kara', 'Minnie', 'Kristi', 'Kaiden', 'Lillie', 'Darrin', 'Marguerite', 'Johnathan', 'Billie', 'Abel', 'Ryker', 'Gael', 'Rowan', 'Lester', 'Herman', 'Omar', 'Conner', 'Janis', 'Jan', 'Devon', 'Gene', 'Monique', 'Kurt', 'Amir', 'Vernon', 'Jayce', 'Shari', 'Belinda', 'Patty', 'Patti', 'Jennie', 'Jerome', 'Mandy', 'Adriana', 'Reagan', 'Sheri', 'Felicia', 'Daniela', 'Clyde', 'Jillian', 'Krista', 'Arya', 'Braden', 'Ricardo', 'Maddox', 'Rachael', 'Christie', 'Cristian', 'Keira', 'Marianne', 'Hadley', 'Lena', 'Emery', 'Nicolas', 'Karina', 'Alison', 'Rylee', 'Sonya', 'Jonah', 'Francisco', 'Duane', 'Nichole', 'Ashanti', 'Vicky', 'Gage', 'Caitlyn', 'Mario', 'Brielle', 'Joy', 'Myles', 'Glen', 'Desiree', 'Mattie', 'Toni', 'Jeanette', 'Charlie', 'Willard', 'Lilly', 'Alvin', 'Chelsey', 'Margie', 'Emmanuel', 'Leilani', 'Candace', 'Opal', 'Jimmie', 'Blanche', 'Gordon', 'Gayle', 'Bob', 'Shelley', 'Legend', 'Adalynn', 'Jordyn', 'Wallace', 'Dawson', 'Everleigh', 'Liliana', 'Jasper', 'Malachi', 'River', 'Bridget', 'Rylan', 'Fernando', 'Melody', 'Mae', 'Perry', 'Cayden', 'Katina', 'Yvette', 'Milo', 'Tami', 'Kassandra', 'Alondra', 'Andres', 'Lewis', 'Athena', 'Dwight', 'Alexia', 'Jenny', 'King', 'Ximena', 'Leon', 'Jonathon', 'Jude', 'Stefanie', 'Manuel', 'Ana', 'Brad', 'Miley', 'Reginald', 'Kellie', 'Javier', 'Lorenzo', 'Kendall', 'Hayley', 'Darin', 'Raelynn', 'Velma', 'Giselle', 'Adriel', 'Milton', 'Karl', 'Carly', 'Kent', 'Geneva', 'Abraham', 'Krystle', 'Paulette', 'Doreen', 'Lizbeth', 'Clayton', 'Summer', 'Stacie', 'Kirk', 'Kate', 'Marquita', 'Ashlyn', 'Cesar', 'Zion', 'Tyrone', 'Meagan', 'Mckenzie', 'Kristopher', 'Hillary', 'Daisy', 'Andre', 'Sam', 'Jaclyn', 'Britney', 'Esmeralda', 'Georgia', 'Ashlee', 'Alana', 'Lynne', 'Cecil', 'Reese', 'Hector', 'Adalyn', 'Damon', 'Edgar', 'Ty', 'Eliza', 'Lyla', 'Elliott', 'Carmen', 'Alisha', 'Erick', 'Elliot', 'Tucker', 'Karter', 'Brooklynn', 'Laila', 'Xander', 'August', 'Beulah', 'Lacey', 'Chandler', 'Muriel', 'Darla', 'Harriet', 'Rhett', 'Matteo', 'Kylee', 'Finn', 'Graham', 'Debora', 'Marley', 'Jaiden', 'Trenton', 'Teri', 'Archer', 'Tracie', 'Ciara', 'Hope', 'Luka', 'Tabitha', 'Guy', 'Aliyah', 'Thiago', 'Aimee', 'Harvey', 'Raven', 'Shelia', 'Ebony', 'Drew', 'Josue', 'Amaya', 'Tasha', 'Damien', 'Alaia', 'Izabella', 'Tammie', 'Sergio', 'Chance', 'Eunice', 'Jazmin', 'Ramona', 'Jaylen', 'Roxanne', 'Rosa', 'Jody', 'Zayden', 'Juliana', 'Rebekah', 'Tori', 'Kari', 'Garry', 'Donovan', 'Clinton', 'Kerry', 'Makenzie', 'Theo', 'Emiliano', 'Enzo', 'Marisa', 'Cassie', 'Bobbie', 'Jakob', 'Alejandra', 'Allan', 'Remi', 'Iris', 'Darius', 'Iker', 'Mathew', 'Diamond', 'Tamika', 'Norah', 'Paris', 'Maximus', 'Eden', 'Hilda', 'Elise', 'Gilbert', 'Roberto', 'Marco', 'Inez', 'Londyn', 'Lonnie', 'Shawna', 'Adrianna', 'Adrienne', 'Sienna', 'Judah', 'Stuart', 'Meredith', 'Karla', 'Mariana', 'Latasha', 'Maryann', 'Abby', 'Camryn', 'Teagan', 'Jermaine', 'Kristie', 'Kyla', 'Atlas', 'Dora', 'Messiah', 'Zane', 'Alberta', 'Ryleigh', 'Arnold', 'Matias', 'Jayceon', 'Ayla', 'Kimberley', 'Yesenia', 'Delaney', 'Elliana', 'Hattie', 'Alaina', 'Barrett', 'Paxton', 'Amara', 'Priscilla', 'Josie', 'Emerson', 'Landen', 'Lila', 'Neil', 'Eloise', 'Angie', 'Jasmin', 'Ada', 'Kenny', 'Israel', 'Tevin', 'Trina', 'Kirsten', 'Corbin', 'Andy', 'Nadia', 'Kelley', 'Emersyn', 'Hanna', 'Kyra', 'Ronda', 'Arabella', 'Jacquelyn', 'Zachery', 'Gregg', 'Ace', 'Pat', 'Anastasia', 'Iesha', 'Claude', 'Ron', 'Nina', 'Sasha', 'Ross', 'Lauryn', 'Robyn', 'Adaline', 'Sidney', 'Drake', 'Maggie', 'Verna', 'Johnnie', 'Finley', 'Jax', 'Shanice', 'Alina', 'Cecilia', 'Walker', 'Doug', 'Nayeli', 'Janie', 'Shanna', 'Bret', 'Beckett', 'Shania', 'Miriam', 'Alivia', 'Daryl', 'Virgil', 'Colt', 'Aniyah', 'Roland', 'Randolph', 'Julianna', 'Lucia', 'Cade', 'Donnie', 'Ruben', 'Myrna', 'Wilbur', 'Trey', 'Mercedes', 'Mckenna', 'Mamie', 'Ariella', 'Estelle', 'Shaquille', 'Lukas', 'Dominick', 'Kyrie', 'Lula', 'Ken', 'Trisha', 'Dianna', 'Sonia', 'Harmony', 'Cristina', 'Callie', 'Tessa', 'Kinley', 'Maurice', 'Presley', 'Ted', 'Bryant', 'Bette', 'Maci', 'Holden', 'Marla', 'Freddie', 'Homer', 'Amari', 'Trent', 'Ashleigh', 'Cadence', 'Keegan', 'Knox', 'Nikki', 'Pedro', 'Alexus', 'Gerardo', 'Rafael', 'Malia', 'Blakely', 'Bria', 'Griffin', 'Kehlani', 'Braylon', 'Tyrese', 'Olga', 'Rudolph', 'Felix', 'Cierra', 'Arlo', 'Fiona', 'Adelyn', 'Morris', 'Dante', 'Ginger', 'Brynn', 'Adonis', 'Brianne', 'Cali', 'Juliette', 'Olive', 'Remington', 'Allyson', 'Juniper', 'Simon', 'Deja', 'Luann', 'Maeve', 'Allie', 'Celeste', 'Arielle', 'Sloane', 'Wendell', 'Mable', 'Gerard', 'Hugh', 'Makenna', 'Addyson', 'Lola', 'Marty', 'Khadijah', 'Emilio', 'Deneen', 'Kyler', 'Lora', 'Kerri', 'Zander', 'Winifred', 'Magnolia', 'Justine', 'Junior', 'Gunner', 'Kiana', 'Catalina', 'Freya', 'Joselyn', 'Joni', 'Timmy', 'Brynlee', 'Dina', 'Flora', 'Devante', 'Leigh', 'Alayna', 'Rosie', 'Shana', 'Skyler', 'Julio', 'Kobe', 'Hubert', 'Dena', 'Aisha', 'Enrique', 'Marcella', 'Sherrie', 'Irving', 'Asia', 'Ember', 'Julissa', 'Erma', 'Bonita', 'Jazmine', 'Joey', 'Jayne', 'Harley', 'Gemma', 'Tobias', 'Haylee', 'Raul', 'Farrah', 'Lucile', 'Fatima', 'Christa', 'Armando', 'Mayra', 'Patrice', 'Leila', 'Kameron', 'Phoenix', 'Serena', 'Rex', 'Keri', 'Killian', 'Savanna', 'Terrence', 'Bernadette', 'Malcolm', 'Imogene', 'Millie', 'Lou', 'Tyson', 'Nash', 'Journee', 'Macy', 'Cash', 'Luther', 'Susie', 'Randal', 'Raquel', 'Faye', 'Daleyza', 'Tatiana', 'Cara', 'Lana', 'Brennan', 'Jana', 'Katelynn', 'Maximiliano', 'Kayleigh', 'Hayes', 'Kailey', 'Reid', 'Vivienne', 'Tonia', 'Jeannie', 'Madeleine', 'Terrance', 'Wade', 'Alberto', 'Charity', 'Dallas', 'Julius', 'Janelle', 'Marcos', 'Lynette', 'Henrietta', 'Cheri', 'Guadalupe', 'Aden', 'Beckham', 'Raegan', 'Shauna', 'Caiden', 'Lane', 'Juliet', 'Fabian', 'Jayda', 'Maude', 'Geoffrey', 'Brenden', 'Kasey', 'Irma', 'Betsy', 'Eula', 'Kira', 'Noelle', 'Lottie', 'Zackary', 'Emanuel', 'Laverne', 'Journey', 'Janine', 'Wilson', 'Brock', 'Sheree', 'Catina', 'Kelvin', 'Jaylah', 'Kash', 'Deana', 'Lara', 'Lorene', 'Gretchen', 'Heaven', 'Forrest', 'Camille', 'Fern', 'Fredrick', 'Ronan', 'Kamila', 'Sonja', 'Angelo', 'Karson', 'Evangeline', 'Antoinette', 'Lexi', 'Kenzie', 'Ashlynn', 'Zara', 'Devonte', 'Titus', 'Lia', 'Horace', 'Jadyn', 'Kali', 'Lorie', 'Marina', 'Alani', 'Sage', 'Rosemarie', 'Aspen', 'Gustavo', 'Latonya', 'Kaydence', 'Myra', 'Byron', 'Dulce', 'Chuck', 'Annabella', 'Tiara', 'Ben', 'Clint', 'Fernanda', 'Yahir', 'Aniya', 'Daxton', 'Carolina', 'Kamryn', 'Marshall', 'Rochelle', 'Samara', 'Aaden', 'Nyla', 'Cortney', 'Willis', 'Katlyn', 'Margot', 'Jonas', 'Zuri', 'Briella', 'Conor', 'Cruz', 'Heath', 'Lilah', 'Anderson', 'Caylee', 'Jamal', 'Joaquin', 'Sade', 'Adelaide', 'Amiyah', 'Mona', 'Alissa', 'Bettie', 'Dixie', 'Lilliana', 'Danna', 'Chelsie', 'Imani', 'Kelsie', 'Brittani', 'Neal', 'Lyric', 'Camilla', 'Hilary', 'Khalil', 'Clifton', 'Trista', 'Brenna', 'Elaina', 'Sammy', 'Gale', 'Therese', 'Roosevelt', 'Thea', 'Clarissa', 'Jaqueline', 'Jett', 'Grady', 'Jensen', 'Kaylie', 'Orville', 'Della', 'Toby', 'Marisol', 'Tristen', 'Shayla', 'Kairo', 'Jeannine', 'Tia', 'Laurel', 'Staci', 'Cohen', 'Crew', 'Amina', 'Hendrix', 'Rodrigo', 'Latisha', 'Pablo', 'Kyleigh', 'Daniella', 'Bodhi', 'Kody', 'Madilyn', 'Nettie', 'Malakai', 'Charlee', 'Maddison', 'Myla', 'Phoebe', 'Amira', 'Tatyana', 'Gideon', 'Lennox', 'Ramon', 'Cathleen', 'Adan', 'Carissa', 'Leia', 'Nickolas', 'Marcy', 'Alisa', 'Audra', 'Branden', 'Kayson', 'Prince', 'Orion', 'Brayan', 'Earnest', 'Lakisha', 'Deandre', 'Kiera', 'Edmund', 'Jarrod', 'Kimora', 'Madalyn', 'Francine', 'Anahi', 'Elsa', 'Alessandra', 'Adelynn', 'Taryn', 'Nakia', 'Daphne', 'Paislee', 'Talia', 'Oakley', 'Saul', 'Kailani', 'Scotty', 'Alayah', 'Maliyah', 'Ali', 'Kizzy', 'Dewey', 'Jeannette', 'Terrie', 'Archie', 'Dorothea', 'Danica', 'Ellis', 'Perla', 'Haven', 'Estrella', 'Atticus', 'Nick', 'Reed', 'Arturo', 'Elisabeth', 'Milani', 'Vonda', 'Emely', 'Johnathon', 'Lowell', 'Annika', 'Kiley', 'Paola', 'Randi', 'Amie', 'Hallie', 'Christop', 'Nelson', 'Alfredo', 'Rihanna', 'Giuliana', 'Mikaela', 'Leticia', 'Dane', 'Desmond', 'Lennon', 'Benny', 'Kaia', 'Rylie', 'Saylor', 'Nikolas', 'Salvatore', 'Talan', 'Ernestine', 'Yaretzi', 'Gia', 'Lorrie', 'Muhammad', 'Roderick', 'Lyle', 'Zayn', 'Kane', 'Jodie', 'Jolene', 'Quentin', 'Demetrius', 'Goldie', 'Karin', 'Keisha', 'India', 'Cleo', 'Ariah', 'Justice', 'Kendrick', 'Jarod', 'Candy', 'Jami', 'Lamont', 'Major', 'Addilyn', 'Delbert', 'Marquis', 'Nikita', 'Nia', 'Braydon', 'Essie', 'Otis', 'Adele', 'Marlon', 'Nico', 'Evelynn', 'Leland', 'Oaklynn', 'Raelyn', 'Tiana', 'Bryanna', 'Freda', 'Lucinda', 'Esteban', 'Bart', 'Gillian', 'Tameka', 'Emilee', 'Jarrett', 'Yasmin', 'Terence', 'Jaelyn', 'Evie', 'Nadine', 'Braylen', 'Gracelynn', 'Odin', 'Kassidy', 'Braeden', 'Emil', 'Harlow', 'Marely', 'Rickie', 'Cherie', 'Destinee', 'Ainsley', 'Brinley', 'Melba', 'Brycen', 'Rachelle', 'Winter', 'Analia', 'Kaelyn', 'Lilith', 'Janiyah', 'Tatum', 'Deloris', 'Rory', 'Ismael', 'Lacy', 'Angeline', 'Audrina', 'Terrell', 'May', 'Romeo', 'Kris', 'Cedric', 'Gracelyn', 'Itzel', 'Matt', 'Ollie', 'Trudy', 'Cairo', 'Halle', 'Leonel', 'Baylee', 'Angelia', 'Aubrie', 'Zaiden', 'Jayson', 'Jaxton', 'Bennie', 'Carlton', 'Callum', 'Sutton', 'Katharine', 'Luella', 'Madisyn', 'Mickey', 'Kathie', 'Camron', 'Tyra', 'Angelique', 'Gwen', 'Christi', 'Felicity', 'Cecelia', 'Chasity', 'Kellen', 'Cheyanne', 'Nehemiah', 'Kade', 'Effie', 'Lesley', 'Royalty', 'Christin', 'Nasir', 'Blair', 'Jenifer', 'Ora', 'Salvador', 'Johanna', 'Sharyn', 'Octavia', 'Rene', 'Jeri', 'Janiya', 'Moises', 'Sallie', 'Ericka', 'Kadence', 'Demi', 'Dayanara', 'Rocky', 'Ariyah', 'Lela', 'Maisie', 'Alaya', 'Kaylani', 'Macie', 'Madyson', 'Addie', 'Clay', 'Luciana', 'Solomon', 'Wilbert', 'Karissa', 'Kamden', 'Noel', 'Sondra', 'Colson', 'Anya', 'Kenya', 'Aylin', 'Jewell', 'Tate', 'Kason', 'Debby', 'Elle', 'Marlee', 'Gianni', 'Iva', 'Amora', 'Sherlyn', 'Skye', 'Willa', 'Nataly', 'Ira', 'Robbie', 'Palmer', 'Keaton', 'Clark', 'Kierra', 'Orlando', 'Tammi', 'Carroll', 'Zachariah', 'Jaslene', 'Frankie', 'Miracle', 'Quinton', 'Tayler', 'Elian', 'Sharron', 'Ari', 'Darian', 'Kaylin', 'Scarlet', 'Brendon', 'Tisha', 'Dahlia', 'Lawson', 'Remy', 'Nylah', 'Denzel', 'Niko', 'Abram', 'Madelynn', 'Reign', 'Mckinley', 'Mekhi', 'Porter', 'Shaniqua', 'Zackery', 'Jazlyn', 'Ervin', 'Winston', 'Averie', 'Ernesto', 'Armani', 'Celia', 'Ezequiel', 'Hailee', 'Wren', 'Leola', 'Trevon', 'Zayne', 'Elisa', 'Jeanine', 'Kennedi', 'Ayanna', 'Corinne', 'Tania', 'Bobbi', 'Lainey', 'Laurence', 'Wendi', 'Aviana', 'Collins', 'Kellan', 'Dexter', 'Mack', 'Lesly', 'Aitana', 'Cyrus', 'Frieda', 'Ophelia', 'Anaya', 'Tabatha', 'Alton', 'Merle', 'Dionne', 'Brandie', 'Addisyn', 'Tamia', 'Rudy', 'Jimena', 'Antoine', 'Landyn', 'Mauricio', 'Everlee', 'Jewel', 'Tierra', 'Gunnar', 'Kathi', 'Lakeisha', 'Tamra', 'Annalise', 'Isiah', 'Kaitlynn', 'Malaysia', 'Haisley', 'Nicolette', 'Paulina', 'Raiden', 'Alta', 'Sullivan', 'Ibrahim', 'Issac', 'Lorena', 'Sarai', 'Irvin', 'Wynter', 'Finnegan', 'Marcie', 'Saundra', 'Aleah', 'Hugo', 'Gisselle', 'Litzy', 'Lizzie', 'Braelynn', 'Sylvester', 'Elyse', 'Etta', 'Otto', 'Grover', 'Jayleen', 'Wilfred', 'Leanne', 'Brenton', 'Cataleya', 'Reece', 'Royce', 'Selma', 'Avianna', 'Simone', 'Deirdre', 'Mathias', 'Kolton', 'Zina', 'Chrystal', 'Kailyn', 'Marci', 'Reba', 'Elva', 'Haleigh', 'Princeton', 'Uriel', 'Cary', 'Matthias', 'Bristol', 'Elbert', 'Elianna', 'Francesca', 'Kamari', 'Ronin', 'Seymour', 'Rocco', 'Lilian', 'Sterling', 'Bradford', 'Maritza', 'Dayana', 'Kalani', 'Melany', 'Esme', 'Leighton', 'Jamari', 'Bowen', 'Brylee', 'Lesa', 'Shaina', 'Viviana', 'Haylie', 'Nanette', 'Mckayla', 'Tennille', 'Eleanore', 'Allisson', 'Maribel', 'Pete', 'Nell', 'Bettye', 'Daren', 'Dream', 'Stevie', 'Lorna', 'Tanisha', 'Carey', 'Colten', 'Davis', 'Jadon', 'Rosanne', 'Ola', 'Milan', 'Jaheim', 'Gannon', 'Chastity', 'Liberty', 'Dax', 'Chandra', 'Regan', 'Brittni', 'Precious', 'Ina', 'Meaghan', 'Izaiah', 'Javon', 'Darnell', 'Alyson', 'Kolby', 'Chantel', 'Kashton', 'Mollie', 'Abril', 'Kensley', 'Lamar', 'Rufus', 'Charleigh', 'Tenley', 'Braelyn', 'Charli', 'Kasen', 'Deacon', 'Royal', 'Augustus', 'Eve', 'Mylee', 'Benson', 'Kaleigh', 'Helene', 'Selah', 'Ryland', 'Triston', 'Cason', 'Zariah', 'Anissa', 'Fay', 'Curt', 'Renata', 'America', 'Stefan', 'Suzette', 'Jaleesa', 'Amya', 'Keenan', 'Lauri', 'Maximilian', 'Annabel', 'Jordon', 'Loren', 'Quincy', 'Rubi', 'Jamaal', 'Larissa', 'Lorelei', 'Margo', 'Susanne', 'Carley', 'Luciano', 'Mohamed', 'Myron', 'Abbey', 'Kyson', 'Danika', 'Jamison', 'Memphis', 'Chadwick', 'Jaydon', 'Will', 'Johnie', 'Selina', 'Claudette', 'Jaliyah', 'Rhys', 'Emelia', 'Yasmine', 'Thalia', 'Janette', 'Bert', 'Breana', 'Kaila', 'Mandi', 'Ed', 'Dorthy', 'Maren', 'Isabela', 'Matilda', 'Brodie', 'Guillermo', 'Alanna', 'Emmalyn', 'Jacoby', 'Carina', 'Aleena', 'Helena', 'Polly', 'Lyndsey', 'Anabelle', 'Emory', 'Laci', 'Aileen', 'Liana', 'Ciera', 'Darcy', 'Julianne', 'Melina', 'Mira', 'Wilder', 'Hank', 'Cristal', 'Cullen', 'Lakesha', 'Avah', 'Callan', 'Lenora', 'Rodger', 'Arline', 'Rashad', 'Shayna', 'Yoselin', 'Abbigail', 'Chanel', 'Phil', 'Astrid', 'Colette', 'Jaylin', 'Leanna', 'Lorri', 'Shiloh', 'Briggs', 'Katy', 'Kian', 'Adolph', 'Jaimie', 'Antonia', 'Tyrell', 'Celine', 'Doyle', 'Tommie', 'Moses', 'Santino', 'Aldo', 'Antonella', 'Liz', 'Poppy', 'Alijah', 'Ahmad', 'Blanca', 'Kiersten', 'Melisa', 'Zyaire', 'Emilie', 'Talon', 'Apollo', 'Elma', 'Johan', 'Kora', 'Bailee', 'Darrel', 'Kylo', 'Elinor', 'Madilynn', 'Nannie', 'Noa', 'Noreen', 'Saniya', 'Brisa', 'Hollie', 'Annmarie', 'Rosalind', 'Dewayne', 'Rhiannon', 'Arjun', 'Robbin', 'Davion', 'Kevon', 'Pierce', 'Eldon', 'Jerald', 'Maryam', 'Devan', 'Jaylon', 'Kourtney', 'Lexie', 'Lilyana', 'Stewart', 'Glenna', 'Kaison', 'Unknown', 'Duncan', 'Leonidas', 'Marquise', 'Ayaan', 'Lucca', 'Tiffani', 'Anika', 'Casandra', 'Ford', 'Ila', 'Dorian', 'Juwan', 'Valarie', 'Charley', 'Emmy', 'Jamarion', 'Laney', 'Amare', 'Baylor', 'Elnora', 'Maia', 'Omarion', 'Estella', 'Meadow', 'Nikolai', 'Stephani', 'Ally', 'Leann', 'Norbert', 'Sherman', 'Jarvis', 'Kirstie', 'Noe', 'Osvaldo', 'Scottie', 'Scot', 'Jaylynn', 'Alonzo', 'Alysha', 'Bridgette', 'Oaklyn', 'Raylan', 'Tristin', 'Nathalie', 'Murray', 'Azalea', 'Daquan', 'Adelina', 'Isaias', 'Elisha', 'Kelsi', 'Kurtis', 'Dee', 'Loyd', 'Case', 'Monte', 'Baker', 'Charmaine', 'Jena', 'Denis', 'Omari', 'Alessia', 'Blaine', 'Gayla', 'Johnna', 'Maranda', 'Kenley', 'Kristian', 'Tamera', 'Elwood', 'Flossie', 'Teddy', 'Ladonna', 'Yulissa', 'Fallon', 'Malani', 'Rodolfo', 'Nathanael', 'Sheldon', 'Darien', 'Henley', 'Jarred', 'Judi', 'Karyn', 'Tripp', 'Eugenia', 'Dior', 'Nixon', 'Buddy', 'Dangelo', 'Legacy', 'Roscoe', 'Skyla', 'Terra', 'Mavis', 'Natalee', 'Percy', 'Elvis', 'Felipe', 'Dusty', 'Kory', 'Stetson', 'Clarice', 'Tyree', 'Deanne', 'Ariya', 'Jaida', 'Burton', 'Hal', 'Jayme', 'Anitra', 'Cassius', 'Infant', 'Jamar', 'Janay', 'Saniyah', 'Vince', 'Galilea', 'Hailie', 'Celina', 'Deena', 'Lea', 'Marlo', 'Yadira', 'Asa', 'Elvira', 'Emberly', 'Jaelynn', 'Jalisa', 'Lawanda', 'Margarita', 'Tianna', 'Jemma', 'Yareli', 'Ahmed', 'Garret', 'Julieta', 'Kaylynn', 'Donte', 'Janae', 'Luanne', 'Carlie', 'Carmela', 'Kaliyah', 'Tre', 'Anabella', 'Aziel', 'Harriett', 'Micaela', 'Rowen', 'Conrad', 'Kailee', 'Edythe', 'Kristal', 'Damion', 'Kieran', 'Stephan', 'Ingrid', 'Kaley', 'Rosetta', 'Braylee', 'Ivanna', 'Jess', 'Cristopher', 'Kimberlee', 'Rena', 'Rusty', 'Alfonso', 'Araceli', 'Chyna', 'Luz', 'Jessa', 'Van', 'Derick', 'Akeem', 'Aryanna', 'Emmitt', 'Jaycee', 'Christen', 'Mariam', 'Dayton', 'Lorelai', 'Tod', 'Zaria', 'Abdiel', 'Jaquan', 'Mireya', 'Nelda', 'Davon', 'Deion', 'Virgie', 'Ashlie', 'Aurelia', 'Essence', 'Kendal', 'Mohammed', 'Keagan', 'Margery', 'Stephany', 'Bernadine', 'Braiden', 'Deshawn', 'Jerri', 'Khaleesi', 'Callen', 'Isis', 'Macey', 'Yazmin', 'Kecia', 'Cannon', 'Chrissy', 'Gilberto', 'Raphael', 'Amos', 'Coty', 'Karsyn', 'Neva', 'Diann', 'Kynlee', 'Lexus', 'Uriah', 'Janessa', 'Madalynn', 'Raheem', 'Tylor', 'Vance', 'Dion', 'Keely', 'Rob', 'Roseann', 'Soren', 'Adley', 'Alia', 'Carmella', 'Jaxen', 'Keanu', 'Monroe', 'Arely', 'Jaron', 'Jeffry', 'Ailani', 'Jaidyn', 'Moshe', 'Rogelio', 'Nyah', 'Rhoda', 'Amirah', 'Jolie', 'Kale', 'Korbin', 'Aiyana', 'Aretha', 'Aarav', 'Cari', 'Deidre', 'Sybil', 'Winnie', 'Zaire', 'Austen', 'Desirae', 'Truman', 'Monty', 'Kaye', 'Abbie', 'Kylan', 'Susana', 'Tomas', 'Denver', 'Britany', 'Greta', 'Lyra', 'Montserrat', 'Trace', 'Dominik', 'Nola', 'Josh', 'Zoie', 'Amani', 'Duke', 'Ivory', 'Tess', 'Kaya', 'Coraline', 'Ramiro', 'Briar', 'Chaz', 'Irwin', 'Gerry', 'Kala', 'Katalina', 'Layton', 'Shyanne', 'Cayson', 'Jasiah', 'Mohammad', 'Zain', 'Zelda', 'Kannon', 'Levar', 'Mariela', 'Edison', 'Katarina', 'Rohan', 'Beatriz', 'Misti', 'Amaia', 'Latanya', 'Sloan', 'Sonny', 'Bo', 'Ermias', 'Giovani', 'Harlan', 'Alexandrea', 'Huxley', 'Liza', 'Zahra', 'Breanne', 'Moriah', 'Santana', 'Coby', 'Dalia', 'Kenzo', 'Shaniya', 'Wells', 'Giana', 'Kimber', 'Shelbi', 'Yusuf', 'Carmelo', 'Lyndon', 'Tariq', 'Jailene', 'Lashonda', 'Novah', 'Rayan', 'Amalia', 'Channing', 'Erwin', 'Jordin', 'Kacie', 'Makai', 'Savanah', 'Shakira', 'Tonja', 'Chace', 'Demarcus', 'Karlee', 'Keshia', 'Samson', 'Yandel', 'Clare', 'Jazlynn', 'Marnie', 'Shonda', 'Yaritza', 'Emmie', 'Kanye', 'Myah', 'Zaylee', 'Boyd', 'Maleah', 'Patience', 'Whitley', 'Ashly', 'Korey', 'Lynnette', 'Sylas', 'Lizette', 'Sydnee', 'Adolfo', 'Amarion', 'Karrie', 'Jaylee', 'Alyce', 'Debi', 'Reyna', 'Gena', 'Josette', 'Danette', 'Julien', 'Lyanna', 'Ashely', 'Esperanza', 'Jeanie', 'Miah', 'Neymar', 'Tillie', 'Alena', 'Lanny', 'Monserrat', 'Azul', 'Boston', 'Kaysen', 'Montana', 'Sariah', 'Cecile', 'Laylah', 'Rhianna', 'Rod', 'Siena', 'Arian', 'Huey', 'Lashawn', 'Alisson', 'Barb', 'Hamza', 'Leyla', 'Caryn', 'Rosanna', 'Sammie', 'Aja', 'Darby', 'Deven', 'Vihaan', 'Addilynn', 'Calista', 'Delia', 'Ensley', 'Kadin', 'Noemi', 'Ares', 'Jacklyn', 'Reina', 'Zelma', 'Dona', 'Lavonne', 'Lylah', 'Marybeth', 'Ulises', 'Kadijah', 'Nalani', 'Shantel', 'Tamiko', 'Briley', 'Cornelius', 'Saige', 'Amiya', 'Crosby', 'Suzan', 'Aliya', 'Damaris', 'Earnestine', 'Aracely', 'Bridgett', 'Jacalyn', 'Jaylene', 'Latosha', 'Marcelo', 'Morton', 'Sanaa', 'Cindi', 'Emerie', 'Harlee', 'Jair', 'Krystina', 'Sincere', 'Alora', 'Benita', 'Mina', 'Deangelo', 'Garland', 'Kisha', 'Maud', 'Millard', 'Cornelia', 'Aranza', 'Berniece', 'Boone', 'Saint', 'Jazmyn', 'Lionel', 'Pierre', 'Xiomara', 'Jaziel', 'Kori', 'Salem', 'Zaid', 'Adyson', 'Letha', 'Rolando', 'Cecily', 'Clementine', 'Hezekiah', 'Jairo', 'Kingsley', 'Madden', 'Ansley', 'Earline', 'Marlena', 'Tiffanie', 'Cayla', 'Chaya', 'Destini', 'Jaxtyn', 'Koa', 'Maryellen', 'Concetta', 'Jagger', 'Kyree', 'Mitzi', 'Sydni', 'Lucian', 'Oaklee', 'Amelie', 'Paityn', 'Louie', 'Reuben', 'Carlee', 'Halie', 'Koda', 'Madge', 'Odessa', 'Sommer', 'Destiney', 'Kaylyn', 'Cherish', 'Finnley', 'Jocelyne', 'Joslyn', 'Kayley', 'Oswaldo', 'Xzavier', 'Lenore', 'Malinda', 'Mara', 'Axton', 'Kareem', 'Kristyn', 'Rhea', 'Davina', 'Roselyn', 'Alycia', 'Kelsea', 'Taliyah', 'Deon', 'Alesia', 'Jayde', 'Kinslee', 'Alessandro', 'Aydan', 'Brennen', 'Catrina', 'Dollie', 'Dara', 'Ilene', 'Elora', 'Iliana', 'Shameka', 'Denice', 'Jakayla', 'Kenia', 'Lailah', 'Bryon', 'Ernie', 'Lilianna', 'Rocio', 'Shelbie', 'Watson', 'Malaya', 'Shepherd', 'Javion', 'Rayna', 'Isamar', 'Nigel', 'Romina', 'Adrianne', 'Aline', 'Dariel', 'Elizabet', 'Fletcher', 'Hadassah', 'Karlie', 'Raekwon', 'Deonte', 'Jefferson', 'Justina', 'Katelin', 'Bentlee', 'Bodie', 'Kenna', 'Lupe', 'Marta', 'Wilmer', 'Claudine', 'Kallie', 'Onyx', 'Ridge', 'Salma', 'Davin', 'Leandro', 'Alvaro', 'Denny', 'Emmalee', 'Brixton', 'Yara', 'Avis', 'Deann', 'Mercy', 'Al', 'Casen', 'Jerrica', 'Maricela', 'Octavio', 'Charlize', 'Dirk', 'Freddy', 'Joelle', 'Liv', 'Valentino', 'Bently', 'Campbell', 'Jamya', 'Lizeth', 'Rosella', 'Alden', 'Edmond', 'Galen', 'Kase', 'Kole', 'Navy', 'Taniya', , 'Jamir', 'Kermit', 'Layne', 'Maegan', 'Jamey', 'Keyshawn', 'Livia', 'Maura', 'Mariyah', 'Ronny', 'Brittanie', 'Chantal', 'Elin', 'Graciela', 'Janna', 'Keyla', 'Ruthie', 'Aron', 'Karly', 'Aliza', 'Donny', 'Moesha', 'Roxann', 'Karli', 'Kaylen', 'Kohen', 'Ledger', 'Milena', 'Nala', 'Akira', 'Ander', 'Camren', 'Janel', 'Loraine', 'Zeke', 'Blaire', 'Coleen', 'Evelin', 'Shellie', 'Taraji', 'Damarion', 'Jaeden', 'Louisa', 'Rebeca', 'Rosalyn', 'Coleman', 'Felecia', 'Kairi', 'Milana', 'Titan', 'Vicente', 'Stan', 'Aliana', 'Kerrie', 'Kip', 'Krysta', 'Chanda', 'Frida', 'Jamila', 'Marianna', 'Darwin', 'Zariyah', 'Demond', 'Hana', 'Janell', 'Tera', 'Thaddeus', 'Arleen', 'Scarlette', 'Davonte', 'Jordynn', 'Abdullah', 'Brentley', 'Citlalli', 'Ellianna', 'Kirstin', 'Lina', 'Mari', 'Robby', 'Capri', 'Koby', 'Mareli', 'Paloma', 'Samir', 'Wilda', 'Britni', 'Marisela', 'Shanika', 'Ivette', 'Kamiyah', 'Lisbeth', 'Melodie', 'Shanae', 'Elissa', 'Emir', 'Giovanna', 'Milagros', 'Nya', 'Ryann', 'Belle', 'Beverley', 'Bradyn', 'Calliope', 'Earlene', 'Emmalynn', 'Marilynn', 'Mitchel', 'Rae', 'Aryan', 'Shad', 'Stephon', 'Ayana', 'Brook', 'Langston', 'Quintin', 'Efrain', 'Iona', 'Valentin', 'Akeelah', 'Antwan', 'Bruno', 'Lyndsay', 'Nita', 'Urijah', 'Cristy', 'Kacey', 'Adison', 'Alyse', 'Cailyn', 'Dimitri', 'Kianna', 'Sunny', 'Lillianna', 'Princess', 'Ursula', 'Averi', 'Corina', 'Giovanny', 'Mitch', 'Shayne', 'Brice', 'Elodie', 'Florine', 'Maynard', 'Amia', 'Arsenio', 'Cori', 'Elmo', 'Mac', 'Treasure', 'Zaniyah', 'Bertie', 'Eliel', 'Markus', 'Shelli', 'Cale', 'Dolly', 'Hadlee', 'Lisette', 'Nichelle', 'Valery', 'Vickey', 'Elton', 'Flynn', 'Hester', 'Journi', 'Lu', 'Darrick', 'Jocelynn', 'Tessie', 'Zechariah', 'Aydin', 'Dayami', 'Jabari', 'Jadiel', 'Kadeem', 'Aryana', 'Elvin', 'Gussie', 'Harmoni', 'Kasandra', 'Pearlie', 'Zhane', 'Dakari', 'Gavyn', 'Jacquline', 'Tamela', 'Alexzander', 'Ariadne', 'Holland', 'Kaiya', 'Merlin', 'Russel', 'Althea', 'Brittny', 'Caren', 'Isabell', 'Racheal', 'Aubrielle', 'Cordell', 'Joselin', 'Shanda', 'Yosef', 'Alysia', 'Dino', 'Estefania', 'Marlin', 'Renae', 'Salina', 'Savion', 'Tinsley', 'Tomeka', 'Canaan', 'Katlin', 'Misael', 'Sky', 'Bronson', 'Reyansh', 'Aya', 'Marleigh', 'Rayden', 'Rayne', 'Draven', 'Humberto', 'Lessie', 'Shamar', 'Giancarlo', 'Kya', 'Latrice', 'Tamatha', 'Alonso', 'Keshawn', 'Lacie', 'Makena', 'Maryanne', 'Natalya', 'Sharlene', 'Ayleen', 'Consuelo', 'Hyman', 'Kyan', 'Reilly', 'Amaris', 'Annemarie', 'Davian', 'Jessika', 'Judie', 'Madisen', 'Rivka', 'Branson', 'Dequan', 'Khari', 'Axl', 'Corine', 'Jaylyn', 'Lulu', 'Marylou', 'Sariyah', 'Brittaney', 'Karma', 'Maxton', 'Roslyn', 'Belen', 'Domonique', 'Giada', 'Meghann', 'Raina', 'Semaj', 'Silvia', 'Vaughn', 'Baby', 'Chana', 'Chiquita', 'Darion', 'Dashawn', 'Agustin', 'Houston', 'Jerrod', 'Carlene', 'Darron', 'Demetria', 'Krish', 'Latonia', 'Leatrice', 'Marva', 'Nathanial', 'Alannah', 'Qiana', 'Vienna', 'Augusta', 'Bryn', 'Emmeline', 'Indie', 'Jacey', 'Lachlan', 'Marlys', 'Milania', 'Sandi', 'Cathryn', 'Geri', 'Iola', 'Itzayana', 'Shante', 'Travon', 'Waverly', 'Ainhoa', 'Azariah', 'Ione', 'Janiah', 'Kirby', 'Odell', 'Marcel', 'Saoirse', 'Aubri', 'Carli', 'Rosalia', 'Shyla', 'Tawana', 'Thad', 'Yuliana', 'Aidyn', 'Dandre', 'Edwina', 'Taya', 'Shyann', 'Alecia', 'Joziah', 'Kaci', 'Kaeden', 'Mylah', 'Naya', 'Rikki', 'Alfreda', 'Dayna', 'Miller', 'Thurman', 'Adalee', 'Candi', 'Chaim', 'Jamel', 'Nona', 'Amayah', 'Aubriella', 'Cleveland', 'Jedidiah', 'Leeann', 'Leota', 'Lochlan', 'Nathaly', 'Ronaldo', 'Shanta', 'Tristian', 'Amias', 'Corrine', 'Erna', 'Kitty', 'Shavon', 'Tadeo', 'Tinley', 'Toccara', 'Alphonse', 'Anton', 'Joana', 'Kaisley', 'Ashli', 'Clair', 'Shaylee', 'Theda', 'Avalynn', 'Jalyn', 'Libby', 'Maliah', 'Merry', 'Sevyn', 'Zendaya', 'Abigayle', 'Anakin', 'Cherry', 'Delmar', 'Dillion', 'Jaret', 'Kalyn', 'Keilani', 'Kye', 'Maudie', 'Alaiya', 'Beyonce', 'Blaze', 'Franco', 'Garrison', 'Graysen', 'Krew', 'Landry', 'Yamileth', 'Christal', 'Paisleigh', 'Sydnie', 'Zora', 'Armand', 'Audriana', 'Cami', 'Reva', 'Earle', 'Kataleya', 'Marques', 'Myranda', 'Novalee', 'Tegan', 'Allyssa', 'Augustine', 'Kristofer', 'Laureen', 'Russ', 'Adilynn', 'Delphine', 'Heavenly', 'Jorden', 'Shea', 'Sylvie', 'Cortez', 'Dinah', 'Geralyn', 'Gilda', 'Jaeda', 'Jovani', 'Maxim', 'Nathalia', 'Adrien', 'Ireland', 'Kaela', 'Reynaldo', 'Tena', 'Claud', 'Clement', 'Erich', 'Kia', 'Leisa', 'Nyasia', 'Shelba', 'Barbra', 'Brecken', 'Enoch', 'Jerrold', 'Kamron', 'Rosalee', 'Dejah', 'Dillan', 'Donn', 'Jerica', 'Kaleena', 'Kyndall', 'Mayson', 'Samiyah', 'Tasia', 'Ward', 'Westin', 'Cordero', 'Deidra', 'Jazlene', 'Kamilah', 'Noelia', 'Shirlee', 'Chelsi', 'Kyro', 'Hassan', 'Heidy', 'Rashida', 'Bellamy', 'Leilany', 'Mylie', 'Shamika', 'Andi', 'Coretta', 'Mariann', 'Calleigh', 'Castiel', 'Devyn', 'Selene', 'Shemar', 'Alyvia', 'Ami', 'Buford', 'Dalary', 'Dani', 'Demario', 'Grey', 'Lucero', 'Magnus', 'Martina', 'Rosalinda', 'Corrie', 'Halley', 'Isai', 'Kayli', 'Lourdes', 'Spenser', 'Aubrianna', 'Jordy', 'Meilani', 'Velvet', 'Aditya', 'Alianna', 'Nayely', 'Vada', 'Berkley', 'Cain', 'Evalyn', 'Persephone', 'Vincenzo', 'Yousef', 'Areli', 'Johana', 'Letitia', 'Yessenia', 'Cyril', 'Bambi', 'Christophe', 'Gauge', 'Gus', 'Keily', 'Alize', 'Berenice', 'Marcellus', 'Syreeta', 'Taniyah', 'Alysa', 'Amoura', 'Atreus', 'Fox', 'Hali', 'Jerilyn', 'Loni', 'Theodora', 'Weldon', 'Magdalena', 'Marin', 'Masen', 'Maximo', 'Mikala', 'Randell', 'Sunshine', 'Tosha', 'Chante', 'Clarisa', 'Keon', 'Laisha', 'Musa', 'Nannette', 'Sarahi', 'Alethea', 'Caleigh', 'Dash', 'Hayleigh', 'Iyana', 'Kenyon', 'Odalys', 'Teena', 'Temperance', 'Abagail', 'Delois', 'Fabiola', 'Jaylan', 'Joesph', 'Konner', 'Mikalah', 'Quiana', 'Sol', 'Westley', 'Banks', 'Bryleigh', 'Devonta', 'Ellison', 'Kesha', 'Kymani', 'Wilhelmina', 'Alphonso', 'Anais', 'Bexley', 'Buffy', 'Darrius', 'Hadleigh', 'Jackeline', 'Ned', 'Rico', 'Veda', 'Leesa', 'Miya', 'Reggie', 'Allene', 'Alva', 'Jianna', 'Karley', 'Noor', 'Savana', 'Wilburn', 'Anders', 'Forest', 'Karol', 'Kortney', 'Lelia', 'Roxanna', 'Vito', 'Aleigha', 'Annalee', 'Dasia', 'Delano', 'Demarion', 'Denisse', 'Jaslyn', 'Jaxxon', 'Jovanni', 'Lakeshia', 'Mindi', 'Promise', 'Roxana', 'Sanford', 'Arleth', 'Brigitte', 'Dominque', 'Pamala', 'Rey', 'Shreya', 'Tanika', 'Andria', 'Carie', 'Cassondra', 'Daisha', 'Danita', 'Henrik', 'Ignacio', 'Jeromy', 'Kenisha', 'Kinsey', 'Maurine', 'Mordechai', 'Oakleigh', 'Renita', 'Samira', 'Tracee', 'Caspian', 'Dania', 'Debrah', 'Emmaline', 'Harleigh', 'Saanvi', 'Beryl', 'Juli', 'Kace', 'Kaylah', 'Raylee', 'Yahaira', 'Yair', 'Abigale', 'Fisher', 'Lindy', 'Neveah', 'Payten', 'Susanna', 'Tomika', 'Windy', 'Yamilet', 'Zavier', 'Christiana', 'Cliff', 'Diya', 'Lilyanna', 'Makaila', 'Maryjane', 'Roxie', 'Sheyla', 'Bree', 'Dessie', 'Karis', 'Kolten', 'Lilia', 'Melva', 'Norris', 'Philomena', 'Roxane', 'Zainab', 'Georgette', 'Griselda', 'Kami', 'Malissa', 'Alesha', 'Aminah', 'Kaidence', 'Marlie', 'Nahla', 'Nallely', 'Scout', 'Zhavia', 'Azaria', 'Kristoffer', 'Merrill', 'Naima', 'Sheridan', 'Stacia', 'Barney', 'Dorris', 'German', 'Jurnee', 'Maison', 'Orval', 'Twila', 'Wiley', 'Aislinn', 'Brantlee', 'Damari', 'Missy', 'Anniston', 'Anson', 'Benicio', 'Chantelle', 'Denisha', 'Jalynn', 'Jaydin', 'Patrica', 'Santos', 'Starr', 'Torrey', 'Alexande', 'Alexandr', 'Arlette', 'Bethzy', 'Jamarcus', 'Nestor', 'Shon', 'Yamilex', 'Anfernee', 'Arden', 'Caydence', 'Cloe', 'Ellsworth', 'Juelz', 'Justus', 'Latifah', 'Zayd', 'Breann', 'Brynleigh', 'Frederic', 'Jeanna', 'Kwame', 'Sharonda', 'Sibyl', 'Gatlin', 'Kandice', 'Seamus', 'Zella', 'Abrielle', 'Anabel', 'Caitlynn', 'Debbi', 'Jaquelin', 'Jaxx', 'Rigoberto', 'Sanai', 'Violeta', 'Bjorn', 'Dorene', 'Jaren', 'Jerod', 'Linsey', 'Porsha', 'Sarina', 'Yasmeen', 'Yuridia', 'Avalyn', 'Dortha', 'Laniyah', 'Marietta', 'Pershing', 'Roni', 'Venus', 'Vikki', 'Bode', 'Booker', 'Brittnee', 'Daria', 'Hollis', 'Kassie', 'Marjory', 'Rio', 'Alvina', 'Georgie', 'Ieshia', 'Jenesis', 'Kanisha', 'Karie', 'Maryjo', 'Melvyn', 'Tamie', 'Telly', 'Anjelica', 'Bryana', 'Eliseo', 'Jasmyn', 'Julisa', 'Kylah', 'Unique', 'Aadhya', 'Coen', 'Felisha', 'Kiarra', 'Lashanda', 'Mayme', 'Pattie', 'Riya', 'Donnell', 'Kailynn', 'Lavern', 'Maira', 'Mcarthur', 'Michell', 'Tea', 'Wrenley', 'Britny', 'Ean', 'Estefani', 'Ishaan', 'Khalani', 'Kiaan', 'Lian', 'Lillyana', 'Neriah', 'Phylicia', 'Tawnya', 'Winona', 'Annabell', 'Blessing', 'Creed', 'Gwyneth', 'Jevon', 'Kaelynn', 'Kamora', 'Malayah', 'Stone', 'Adamaris', 'Aspyn', 'Brogan', 'Callahan', 'Dannie', 'Dian', 'Egypt', 'Elina', 'Mechelle', 'Ocean', 'Thatcher', 'Aila', 'Cordelia', 'Kizzie', 'Mylo', 'Ryne', 'Tory', 'Arron', 'Brionna', 'Haiden', 'Iyla', 'Jaunita', 'Shanon', 'Sherrill', 'Tayla', 'Ameer', 'Braedon', 'Iyanna', 'Kamdyn', 'Michel', 'Oma', 'Shanequa', 'Shannan', 'Tru', 'Aedan', 'Blaise', 'Holli', 'Kayleen', 'Melania', 'Nicky', 'Verda', 'Aiyanna', 'Eboni', 'Estevan', 'Gaven', 'Siobhan', 'Stefani', 'Basil', 'Camdyn', 'Catharine', 'Ester', 'Harriette', 'Izabelle', 'Jannie', 'Jed', 'Richelle', 'Tiera', 'Tyesha', 'Abe', 'Ayva', 'Fran', 'Lyn', 'Queen', 'Shianne', 'Zoya', 'Breonna', 'Carleigh', 'Dudley', 'Erykah', 'Gaige', 'Hakeem', 'Kandace', 'Lavar', 'Tanesha', 'Xena', 'Alaric', 'Ambrose', 'Cheryle', 'Dario', 'Dottie', 'Glynis', 'Jailyn', 'Kamya', 'Kensington', 'Latrell', 'Lesia', 'Malaki', 'Marlowe', 'Benton', 'Cathie', 'Emogene', 'Flor', 'Herschel', 'Joseline', 'Jovie', 'Katherin', 'Kelis', 'Kiel', 'Lorine', 'Makala', 'Anjanette', 'Boden', 'Kyndal', 'Linwood', 'Wilford', 'Zola', 'Amiah', 'Audrianna', 'Birdie', 'Cambria', 'Emani', 'Idris', 'Kaiser', 'Kathrine', 'Lisha', 'Roseanna', 'Shay', 'Adriane', 'Austyn', 'Avayah', 'Crissy', 'Cristin', 'Jeramiah', 'Lon', 'Merrick', 'Pyper', 'Tatianna', 'Trevin', 'Vern', 'Alexys', 'Elyssa', 'Halo', 'Isadore', 'Jessi', 'Johnpaul', 'Katia', 'Khalid', 'Louann', 'Martika', 'Pansy', 'Reanna', 'Rodrick', 'Alaysia', 'Anneliese', 'Ashtyn', 'Cael', 'Citlali', 'Elouise', 'Errol', 'Giavanna', 'Janeen', 'Mellissa', 'Nikia', 'Raya', 'Ulysses', 'Xavi', 'Gigi', 'Rianna', 'Symone', 'Vanesa', 'Bayleigh', 'Deron', 'Dilan', 'Donavan', 'Jovan', 'Bonny', 'Garth', 'Georgina', 'Hans', 'Jakobe', 'Leandra', 'Nakita', 'Brea', 'Emerald', 'Jamiya', 'Kahlil', 'Katlynn', 'Laraine', 'Mariel', 'Maylee', 'Shavonne', 'Terese', 'Dariana', 'Izayah', 'Jazzlyn', 'Jorja', 'Kloe', 'Konnor', 'Tarah', 'Wesson', 'Yehuda', 'Aanya', 'Aliah', 'Carolee', 'Cristiano', 'Ivana', 'Louella', 'Stormi', 'Teressa', 'Valorie', 'Zakary', 'Antony', 'Aric', 'Brianda', 'Danelle', 'Juana', 'Kalie', 'Leigha', 'Tad', 'Alene', 'Coy', 'Dawna', 'Emmarie', 'Freyja', 'Karon', 'Rolland', 'Samiya', 'Artemis', 'Brandan', 'Bridger', 'Cristofer', 'Kaycee', 'Kendyl', 'Marlen', 'Zaniya', 'Aleta', 'Carmine', 'Dalilah', 'Emmet', 'Gibson', 'Gino', 'Jammie', 'Kabir', 'Pasquale', 'Riaan', 'Tamya', 'Alexandro', 'Audie', 'Beatrix', 'Brysen', 'Eithan', 'Enid', 'Kati', 'Kyron', 'Nikhil', 'Shalonda', 'Valencia', 'Debbra', 'Jonna', 'Ladarius', 'Luisa', 'Murphy', 'Nyomi', 'Tawanda', 'Adilene', 'Brandyn', 'Cielo', 'Deegan', 'Ephraim', 'Ferdinand', 'Kalli', 'Katerina', 'Keara', 'Marceline', 'Portia', 'Stoney', 'Taja', 'Addalyn', 'Camilo', 'Daija', 'Dylon', 'Garnet', 'Garrick', 'Jolette', 'Kadyn', 'Marquez', 'Peggie', 'Pennie', 'Ruthann', 'Violette', 'Achilles', 'Aubriana', 'Eryn', 'January', 'Josselyn', 'Judson', 'Kalel', 'Kamille', 'Monika', 'Priscila', 'Vesta', 'Cicely', 'Dwain', 'Ellery', 'Kenadie', 'Nailah', 'Quinten', 'Rich', 'Rilynn', 'Rubye', 'Seraphina', 'Aarya', 'Anjali', 'Carlotta', 'Honesty', 'Hoover', 'Jaleel', 'Jazmyne', 'Krysten', 'Leora', 'Nan', 'Nathen', 'Trena', 'Zhuri', 'Bradly', 'Carolann', 'Charleston', 'Eliezer', 'Gonzalo', 'Izabel', 'Jakari', 'Jenelle', 'Lissette', 'Lynsey', 'Mai', 'Melani', 'Mozelle', 'Sofie', 'Angeles', 'Brandee', 'Broderick', 'Jovanny', 'Keeley', 'Latricia', 'Laylani', 'Leena', 'Leone', 'Maddie', 'Marni', 'Mazikeen', 'Niklaus', 'Retha', 'Sekani', 'Stormy', 'Wayde', 'Zahir', 'Zana', 'Aries', 'Eleanora', 'Kael', 'Karyme', 'Kyng', 'Leilah', 'Majesty', 'Rylen', 'Spring', 'Vivaan', 'Yadiel', 'Abrianna', 'Asha', 'Elda', 'Jerimiah', 'Maximillian', 'Arnav', 'Cristobal', 'Heriberto', 'Jamiyah', 'Jaydan', 'Jedediah', 'Keyon', 'Mayte', 'Mervin', 'Millicent', 'Bear', 'Braulio', 'Jeremias', 'Kylen', 'Laquita', 'Rashawn', 'Sahara', 'Samatha', 'Taina', 'Trever', 'Vivien', 'Yisroel', 'Alistair', 'Evalynn', 'Ferne', 'Guinevere', 'Niki', 'Nori', 'Raylynn', 'Arly', 'Buster', 'Eddy', 'Karmen', 'Londynn', 'Nautica', 'Robb', 'Slade', 'Suri', 'Tarsha', 'Aarna', 'Ayan', 'China', 'Deasia', 'Harris', 'Kenji', 'Sailor', 'Turner', 'Zakai', 'Barton', 'Brookelyn', 'Ciji', 'Khiry', 'Maite', 'Shaquan', 'Winfred', 'Aida', 'Aleia', 'Avi', 'Emiliana', 'Jaylani', 'Jerad', 'Jovany', 'Lidia', 'Lillyanna', 'Osiris', 'Starla', 'Tyrek', 'Venita', 'Yael', 'Chynna', 'Ginny', 'Harlem', 'Jionni', 'Koen', 'Kristan', 'Makhi', 'Ailyn', 'Brant', 'Cornell', 'Daja', 'Darci', 'Destin', 'Fanny', 'Indigo', 'Jerrell', 'Leif', 'Samaria', 'Shaila', 'Sharla', 'Tana', 'Adler', 'Bernardo', 'Brookelynn', 'Daron', 'Laniya', 'Love', 'Mustafa', 'Renada', 'Rosalina', 'Zev', 'Calum', 'Everley', 'Kaleah', 'Keila', 'Loriann', 'Mikaila', 'Nyra', 'Venessa', 'Dereon', 'Eason', 'Estefany', 'Immanuel', 'Jesica', 'Loyalty', 'Makenzi', 'Marylyn', 'Mccoy', 'Seven', 'Shepard', 'Azrael', 'Chevy', 'Dallin', 'Evette', 'Jaleah', 'Lluvia', 'Malakhi', 'Nikole', 'Odalis', 'Sherita', 'Soraya', 'Zack', 'Deb', 'Emalee', 'Jacque', 'Jaycob', 'Jayse', 'Justyn', 'Karim', 'Karleigh', 'Pranav', 'Abbygail', 'Avani', 'Cher', 'Dovie', 'Harding', 'Jahiem', 'Jeramy', 'Kinlee', 'Shasta', 'Ahmir', 'Baylie', 'Cal', 'Elia', 'Gisele', 'Janya', 'Jeremie', 'Kennith', 'Milah', 'Milford', 'Omer', 'Raymundo', 'Shanaya', 'Antionette', 'Ayah', 'Brittnie', 'Candis', 'Cletus', 'Deshaun', 'Ethen', 'Kinleigh', 'Leta', 'Viridiana', 'Yadhira', 'Gracyn', 'Ima', 'Jersey', 'Jonael', 'Laken', 'Leela', 'Samya', 'Shara', 'Tawanna', 'Casie', 'Charleen', 'Chevelle', 'Darleen', 'Janene', 'Jeana', 'Kaylan', 'Kiya', 'Naila', 'Preslee', 'Riggs', 'Taurean', 'Trinidad', 'Aniah', 'Bernie', 'Brissa', 'Carlo', 'Codey', 'Cyndi', 'Haden', 'Jericho', 'Jones', 'Lura', 'Migdalia', 'Rhylee', 'Yahya', 'Yajaira', 'Yaretzy', 'Betzy', 'Clover', 'Damir', 'Freeman', 'Hortense', 'Javonte', 'Jubilee', 'Kalia', 'Lianna', 'Trish', 'Antwon', 'Bertram', 'Deandra', 'Elayna', 'Jerold', 'Kelcie', 'Kyara', 'Landin', 'Roseanne', 'Shawnee', 'Aarush', 'Adela', 'Albina', 'Cydney', 'Destany', 'Emme', 'Kylian', 'Shae', 'Suzy', 'Toya', 'Carsen', 'Eris', 'Foster', 'Gerri', 'Hershel', 'Kelton', 'Kenyatta', 'Magen', 'Truett', 'Adilyn', 'Annelise', 'Chelsy', 'Corinna', 'Edgardo', 'Floy', 'Imran', 'Keven', 'Lanie', 'Sonji', 'Syble', 'Vernice', 'Chanelle', 'Coral', 'Dafne', 'Edsel', 'Freida', 'Janney', 'Lauretta', 'Makaylah', 'Makiyah', 'Rowena', 'Syed', 'Trystan', 'Tyshawn', 'Alanah', 'Cillian', 'Deondre', 'Fredric', 'Jaimee', 'Kinzley', 'Layan', 'Male', 'Neha', 'Normand', 'Shani', 'Analise', 'Annamarie', 'Candida', 'Citlaly', 'Elon', 'Johann', 'Maddux', 'Maisy', 'Malka', 'Nanci', 'Nery', 'Shaniyah', 'Shmuel', 'Zena', 'Zyair', 'Aditi', 'Andreas', 'Anisa', 'Arissa', 'Coraima', 'Harlyn', 'Hiram', 'Jaci', 'Jaedyn', 'Jamia', 'Jayvion', 'Marilee', 'Mellisa', 'Minerva', 'Nariah', 'Rileigh', 'Rome', 'Samaya', 'Simeon', 'Star', 'Tenisha', 'Zayla', 'Annaliese', 'Braylin', 'Carsyn', 'Casimir', 'Darrion', 'Gertie', 'Josef', 'Kamilla', 'Lyman', 'Marigold', 'Natali', 'Rasheed', 'Triniti', 'Tyreke', 'Vida', 'Abner', 'Charla', 'Cinda', 'Colter', 'Domenic', 'Dontae', 'Elana', 'Elvera', 'Jessenia', 'Kamren', 'Richie', 'Sapphire', 'Vayda', 'Addalynn', 'Agatha', 'Brayson', 'Brynley', 'Danyelle', 'Evangelina', 'Hensley', 'Isaak', 'Jad', 'Karime', 'Malorie', 'Tatyanna', 'Geovanni', 'Greysen', 'Jarett', 'Jencarlos', 'Jordi', 'Lexis', 'Maelynn', 'Nuri', 'Rishi', 'Tawny', 'Una', 'Eliot', 'Garett', 'Grecia', 'Kasie', 'Maribeth', 'Myrtis', 'Najee', 'Nicolle', 'Oleta', 'Rowyn', 'Shannen', 'Shiela', 'Talen', 'Wes', 'Alyssia', 'Bishop', 'Brissia', 'Bud', 'Ivonne', 'Jahir', 'Jesiah', 'Kunta', 'Mikael', 'Nohely', 'Addelyn', 'Amal', 'Ananya', 'Evelina', 'Everest', 'Iridian', 'Jamil', 'Jhene', 'Lathan', 'Lonny', 'Margret', 'Meyer', 'Serina', 'Jeramie', 'Katheryn', 'Korbyn', 'Maiya', 'Mallorie', 'Nairobi', 'Vilma', 'Yarely', 'Zyon', 'Andie', 'Charissa', 'Danae', 'Jacie', 'Kraig', 'Mariano', 'Maybelle', 'Tyrique', 'Annabeth', 'Burl', 'Codie', 'Darcie', 'Devontae', 'Dori', 'Edie', 'Everette', 'Jacquelin', 'Madonna', 'Menachem', 'Niya', 'Priya', 'Tatia', 'Benedict', 'Bowie', 'Danial', 'Decker', 'Dhruv', 'Evita', 'Jayvon', 'Kahlani', 'Khadija', 'Lilyann', 'Malak', 'Marcela', 'Maxx', 'Meera', 'Merrily', 'Sherie', 'Shirl', 'Torin', 'Aayan', 'Charisse', 'Contina', 'Joslynn', 'Meir', 'Shaquana', 'Sharen', 'Tallulah', 'Dannielle', 'Durell', 'Joanie', 'Lev', 'Micayla', 'Miyah', 'Nelly', 'Newton', 'Odis', 'Rylynn', 'Shaniece', 'Tiesha', 'Wilton', 'Corban', 'Dakotah', 'Filomena', 'Gianluca', 'Kaniya', 'Keanna', 'Krystin', 'Prisha', 'Shanell', 'Shawnte', 'Sherryl', 'Soleil', 'Somaya', 'Yaakov', 'Ariyana', 'Arlen', 'Ciarra', 'Colbie', 'Dalila', 'Delma', 'Fawn', 'Gizelle', 'Inaya', 'Izzabella', 'Jael', 'Kacen', 'Makiya', 'Tresa', 'Wilfredo', 'Yurem', 'Alli', 'Amarah', 'Cayde', 'Cinthia', 'Dailyn', 'Delanie', 'Delmer', 'Josefina', 'Khalilah', 'Kylene', 'Sabastian', 'Taylin', 'Tyanna', 'Atharv', 'Grisel', 'Inaaya', 'Jasen', 'Jemal', 'Jenni', 'Jovanna', 'Kalene', 'Karsen', 'Kiefer', 'Lakelyn', 'Lenard', 'Maksim', 'Martine', 'Orpha', 'Tabetha', 'Tahj', 'Yamile', 'Yasir', 'Andon', 'Cambree', 'Chiara', 'Kenleigh', 'Kenzi', 'Kirra', 'Mychal', 'Nakisha', 'Trevion', 'Vivianna', 'Anayah', 'Ardis', 'Celena', 'Cianna', 'Cinnamon', 'Dorinda', 'Germaine', 'Kandi', 'Karri', 'Knowledge', 'Kolt', 'Krissy', 'Laquan', 'Manuela', 'Marnita', 'Mika', 'Ria', 'Treyton', 'Tyriq', 'Tyron', 'Amyah', 'Christel', 'Daylen', 'Deyanira', 'Efren', 'Geary', 'Graeme', 'Jai', 'Kaytlin', 'Kelan', 'Kellee', 'Kooper', 'Lettie', 'Mandie', 'Mikel', 'Miriah', 'Nira', 'Shanelle', 'Trae', 'Treyvon', 'Zamir', 'Ashlea', 'Carisa', 'Carrol', 'Cedrick', 'Emi', 'Jaycie', 'Kaine', 'Margarette', 'Maycee', 'Shardae', 'Taj', 'Takisha', 'Tiarra', 'Aloysius', 'Analeigh', 'Briseida', 'Dayanna', 'Donita', 'Javen', 'Kaius', 'Kynslee', 'Lenny', 'Magdalene', 'Pharaoh', 'Sheilah', 'Stephenie', 'Verla', 'Zavion', 'Adin', 'Aksel', 'Alpha', 'Benito', 'Blayke', 'Cailey', 'Danilo', 'Derik', 'Djuna', 'Doretha', 'Francisca', 'Janaya', 'Kanesha', 'Keziah', 'Lona', 'Melia', 'Rayyan', 'Shena', 'Siya', 'Yulisa', 'Adell', 'Amyra', 'Carrington', 'Cherri', 'Dorotha', 'Justen', 'Kaylene', 'Landan', 'Olin', 'Petra', 'Ricki', 'Salena', 'Trayvon', 'Yetta', 'Zaya', 'Alexi', 'Audree', 'Baron', 'Brayleigh', 'Cameryn', 'Carys', 'Charisma', 'Cormac', 'Eisley', 'Isela', 'Isha', 'Josias', 'Kacy', 'Kaelin', 'Meg', 'Noble', 'Rahul', 'Shantell', 'Shlomo', 'Batsheva', 'Beck', 'Bilal', 'Cassian', 'Celestine', 'Crysta', 'Daijah', 'Davy', 'Fidel', 'Hellen', 'Jesenia', 'Nichol', 'Stephaine', 'Syncere', 'Taytum', 'Aliyana', 'Amberly', 'Annaleigh', 'Azucena', 'Cashton', 'Cienna', 'Deedee', 'Demarco', 'Emberlee', 'Jania', 'Jasmyne', 'Joretta', 'Lilyan', 'Roselynn', 'Shelva', 'Shonna', 'Tavion', 'Twyla', 'Tyquan', 'Caelyn', 'Deklan', 'Evander', 'Jackelyn', 'Kaisen', 'Kandy', 'Lillyan', 'Madysen', 'Marlyn', 'Olen', 'Shimon', 'Tangela', 'Tressa', 'Zooey', 'Bettina', 'Brittnay', 'Elroy', 'Ezrah', 'Halee', 'Jenilee', 'Khaza', 'Latoria', 'Mykayla', 'Racquel', 'Reta', 'Youssef', 'Ziva', 'Alda', 'Britta', 'Diandra', 'Elly', 'Fredy', 'Kaaren', 'Linkin', 'Maliya', 'Velda', 'Xochitl', 'Aayden', 'Barbie')
$Global:BadPasswords = @('123456','123456789','qwerty','password','12345678','111111','qwerty123','1q2w3e','1234567','abc123','1234567890','123123','DEFAULT','password1','000000','12345','iloveyou','1q2w3e4r5t','qwertyuiop','123321','654321','666666','123456a','1234','dragon','monkey','1qaz2wsx','1q2w3e4r','123qwe','121212','7777777','qwe123','123','987654321','zxcvbnm','@hotmail.com','123abc','a123456','555555','myspace1','qwerty1','112233','222222','qazwsx','asdfghjkl','10pace','123123123',,'target123',,'tinkle','gwerty','1g2w3e4r','159753','zag12wsx','gwerty123','1234qwer','princess','computer','football','michael','12345a','11111111','777777','aaaaaa','sunshine','ashley','123654','789456123','asdfgh','999999','daniel','shadow','abcd1234','iloveyou1','superman','123456789a',,'888888','master','qwer1234','samsung','j38ifUbn',,'88888888','azerty','12qwaszx','q1w2e3r4','q1w2e3r4t5y6','baseball','FQRG7CS493','princess1','jessica','3rJs1la7qE','asd123','gfhjkm','asdasd','charlie','soccer','789456','yuantuo2012','Sojdlg123aljg','0123456789','333333','Status','jordan23','jordan','football1','a12345','131313','love123','welcome','thomas','liverpool','zxcvbn','1111111','Password','987654','123456q','0987654321','passer2009','monkey1','147258369','blink182','michelle','159357','30media','nicole','qazwsxedc','michael1','pokemon','102030','andrew','1234561','naruto','anthony','joshua','justin','101010','lovely','11111','babygirl1','jennifer','hunter','59trick','123456','qwerty12','1111111111',,'qweasdzxc','love','tigger','robert','x4ivygA51F','linkedin','12341234','1qaz2wsx3edc','secret','5201314','00000000','hello1','andrea','trustno1','marina','babygirl','qweqwe','24crow','12344321','angel1','asdf1234','iloveyou2','59mile','010203','freedom','parola','purple','q1w2e3r4t5','passw0rd','letmein','147258','matthew','buster','hannah','1qazxsw2','loveme','mother','chocolate','google','chelsea','william','pakistan','george','asdf','basketball',,'amanda','internet','jessica1','samantha','summer','q1w2e3','batman','12345678910','flower',,'friends','alexander','12345qwert','maggie','iloveu','anthony1','forever',,'butterfly','mustang','a838hfiD','baseball1','qweasd','1234567891','charlie1','martin','london','1111','212121','lol123','starwars','money1','12345q','whatever','nikita','soccer1','pepper','golfer','cookie','harley','orange','qwert','junior','111222','mynoob','232323','family','loveyou','superman1','number1','joseph','jasmine','arsenal','patrick','xbox360','123654789','matrix','!ab#cd$','ginger','0','ghbdtn','abcdef','11223344',,'hello123','sunshine1','snoopy','147852','thehatch','admin','hello','qwertyu','taylor','3Odi15ngxB','cheese','87654321','diamond','eminem','jonathan',,'mercedes','brandon','password2','ashley1','50cent','147852369','qqqqqq','melissa','444444','oliver','1234554321','a123456789','zaq12wsx','29rsavoy','mylove','password12','bailey','mickey','sophie','456789','victoria','richard','benjamin','sandra','christian','school','password123','1v7Upjw3nT','VQsaBLPzLa','123789','123qweasd','yellow','banana','myspace','qwertyui','qwerty12345','shadow1','barcelona','abcdefg','uQA9Ebw445','natasha','jordan1','gabriel','angela','qwaszx','lovers','prince','peanut','nicole1','brandon1','antonio','monster','qazxsw','apple','silver','carlos','nathan','samuel','love12','elizabeth','hockey','chicken','252525','adidas','slipknot','xxxxxx','1q2w3e4r5t6y','741852963','metallica','0000000000','chris1','angels',,'abc','1','ferrari','matthew1','456123','asdfasdf','super123','999999999','nirvana','Password1','iw14Fi9j','vanessa','rainbow','N0=Acc3ss','spiderman','dragon1','morgan','red123','welcome1','america','bubbles','jackson','cjmasterinf','austin','0123456','liverpool1','juventus','123456789q','happy1','computer1','142536','alexis','290966','madison','wall.e','tudelft','DIOSESFIEL','william1','U38fa39','dpbk1234','PE#5GZ29PTZMSE','7654321','asdasd5','steven','michelle1','4815162342','cocacola','zzzzzz','lauren',,'ronaldo','amanda1','nicholas','lucky1','jasmine1','1234567a','P3Rat54797','daniel1','bandit','danielle','stella','victor','666','valentina','pokemon1','zxc123','scooter','d2Xyw89sxJ','yamaha','tinkerbell','justin1','hunter1','!','user','123asd','andrew1','qaz123','D1lakiss','1234abcd','monica','chicken1','098765','rachel','purple1','destiny','hahaha','mommy1','a1b2c3d4','james1','tennis','a1b2c3','friend','3d8Cubaj2E',,'angel','Exigent','alexandra','loulou','nicolas','confirmed','852456','qazwsx123','smokey','jasper','edward','chelsea1','sergey','booboo','casper','november','canada','success','sabrina','butterfly1','heather','robert1','chester','buddy1','qqww1122','124578','nothing','123456s','iG4abOX4','patricia','12121212','0000','chocolate1','freedom1','dIWtgm8492','hellokitty','scorpion','dennis','123456m','hannah1','Million2','phoenix','135790','olivia','159951','thunder','sweety','aa123456','123hfjdk147','1029384756','america1','jennifer1','spider','barbie','123qwe123','sebastian','johnny','december','cookie1','134679','david1','qwerty123456','rebecca','123qweasdzxc','madison1','dakota','lalala','carolina','caroline','mustang1','adrian','1342','loveme1','diamond1','charles','vincent','753951','samantha1','lovelove','guitar','55555','1password','elizabeth1','joshua1','taylor1','jeremy','buster1','elephant','12413','421uiopy258','whatever1','cameron','midnight',,'veronica','lovely1','startfinding',,'daddy1','merlin','pretty','louise','dallas','beautiful','010101','tigger1',,'dolphin','thomas1','music1','cristina','a1234567','andrey','PBKDF1','qazqaz','daniela','family1','yankees','1122334455','$HEX','diablo','202020','246810','harley1','kristina','741852','cheese1','YAgjecc826','myspace123','0000000','sakura','genius','Groupd2013','scooby','sparky','newyork','manchester','winner','qwert1','spongebob1','1a2b3c','september','crystal','doudou','spongebob','123456b','tigers','stephanie','zxcvbnm1','creative','tweety','9876543210','friends1','!~!1','jessie','W5tXn36alfW','apples','gemini','shannon','ia2frS','fender','heaven','RFtgyh','summer1','winston','iq123SRgv','123456abc','master1','toyota','555666','cooper','test123','1234512345','charlotte','maverick','jackie','peaches','mexico','fylhtq','1a2b3c4d','111222tianya','151515','lakers','maggie1','qwert123','patrick1','claudia','456456','12345678a','cherry','leonardo','hotmail','heather1','changeme','muffin','123456d','mexico1','lover1','samson','soleil','batman1','precious','poohbear','alexander1','bubbles1','yankees1','badboy','manuel','951753',,'windows','123123a','qwerty1234','963852741','pepper1','compaq','karina','flowers','melissa1','m123456','s123456','vfhbyf','garfield','iloveu2','naruto1','321321','tiffany','NULL','klaster','cowboys1','asdf123','isabella',,'g9l2d1fzPY','q123456','emmanuel','carmen',,'beauty','rabbit',,'peanut1','murphy','albert','1314520','scorpio','martina','vfrcbv','jackson1','raiders1','mother1','softball','asdfghjkl1','00000','q12345','qwert12345','dexter','richard1','popcorn',,'brittany','123456123','ranger','123456j','swordfish','melanie','steelers','angelo','fernando','marlboro','onelove','boomer',,'monster1','123456z','brandy','august','twilight','paSSword',,'slipknot1','rocky1','apple1','icecream','nastya','samsung1','angelina','a','ginger1','bismillah','career121','darkness','007007','sammy1','iloveyou!','newyork1','winter','141414','motorola','miguel','kimberly','blessed1','spiderman1','flower1','october','barney','yellow1','krishna','sayang','asdfghjk','destiny1','snickers','police','money','9379992','barbara','tiger1','coffee','passion','rangers','kitten','cowboys','55555555','abc123456','christine','california','alyssa','greenday','simone','pass123','hiphop','b123456','123456c','logitech','eagles','marseille',,'shorty','fktrcfylh','yfnfif','qwerty7',,'012345','minecraft','portugal','arsenal1','christ','natalia','789789','denise','scooter1','454545','david','awesome','svetlana','cowboy','maxwell','horses','sydney','florida','baby123',,'dancer','mnbvcxz','slayer','fatima','beautiful1','123456k','z123456','joseph1','aaaaaaaa','woaini','rockstar','blessed','iloveu1','bonnie','iloveme','lollipop','fyfcnfcbz','7758521','alejandro','roberto','123454321',,'natalie','cassie','letmein1','mickey1','pumpkin','francis','fishing','trinity','bond007','forever1','player','22222222','5555555','turtle','lollol','isabelle','ssssss','cameron1','austin1','kitty1','fluffy','lastfm','orange1','123qaz','metallica1','alicia','1123581321',,'courtney','corvette','bonjour','vladimir','azertyuiop','121314','pookie','golden','bailey1',,'green1','242424','booboo1','cambiami','123698745','christian1','starwars1',,'myspace2','abc1234','tyler1','lucky7','marine','234567','black1','music','snowball',,'j123456','5555555555','arthur','guitar1','asdasdasd','remember','people','666999','junior1','camille','andrei','crazy1','090909','brooklyn','786786',,'wilson',,'danielle1','asdfgh1','chicago','111222333','simple','teresa','d123456','456852','123456aa','pamela','asdfjkl','321654','catherine','secret1','boston','mmmmmm','father','shelby','1478963','pa55word','marcus','brittany1',,'123451','aaron431','123456l','babyboy1','maksim','george1','shorty1','molly1','qti7Zxh18U','77777777','iloveyou12','smokey1','password!',,'willow','angel123','i','superstar','bubba1','qwerasdf','123456t','sharon','159159','tucker','love13','dolphin1','raiders','connor','santiago','PASSWORD','qw123321','hammer','monika',,'bulldog','sasuke','12345qwerty','john316','cricket','zxcvbnm123','freddy','asdfghj','marvin','loveyou1','porsche','nissan','nathan1','redsox','marley','jason1','friendster','111111a','warcraft','pantera','hotdog','sweetie','tamara','player1','lauren1','qwerty321','kenneth','pretty1','kawasaki','6V21wbgad','google1',,'shopping','rainbow1','iceman','tiffany1','chris')
$Global:HighGroups = @('Office Admin','IT Admins','Executives');
$Global:MidGroups = @('Senior management','Project management');
$Global:NormalGroups = @('marketing','sales','accounting');
$Global:BadACL = @('GenericAll','GenericWrite','WriteOwner','WriteDACL','Self','WriteProperty');
$Global:ServicesAccountsAndSPNs = @('mssql_svc,mssqlserver','http_svc,httpserver','exchange_svc,exserver');
$Global:CreatedUsers = @();
$Global:AllObjects = @();
$Global:Domain = "";
$Global:TargetOU = ""

$Global:DomainBreachState = [ordered]@{
    Domain             = ""
    Timestamp          = ""
    TargetOU           = ""
    OUCreated          = $false
    PasswordPolicy     = @{}
    SMBSigningEnabled  = $true
    SMBSigningRequired = $true
    Users              = @()
    Groups             = @()
    ServiceAccounts    = @()
    ASREPUsers         = @()
    DnsAdminsUsers     = @()
    DnsAdminsGroups    = @()
    DCsyncUsers                      = @()
    BadACLs                          = @()
    UnconstrainedDelegationUsers     = @()
    UnconstrainedDelegationComputers = @()
    SchemaAdminUsers                 = @()
    PrivilegedKerberoastUsers        = @()
    ReversibleEncryptionUsers        = @()
    DesEncryptionUsers               = @()
    PasswordNeverExpiresUsers        = @()
    SIDHistoryUsers                  = @()
    GuestEnabled                     = $false
    PreWin2000AuthUsers              = $false
    LMHashEnabled                    = $false
    NullSessionEnabled               = $false
    SMBv1Enabled                     = $false
    SpoolerRunning                   = $false
    LDAPSigningDisabled              = $false
    OrigSpoolerStartType             = ""
    OrigSMBv1Enabled                 = $false
    OrigLMHash                       = 1
    OrigNullSession                  = 1
    OrigLDAPSigning                  = 2
    KrbtgtPwdLastSetModified         = $false
    KrbtgtOrigPwdLastSet             = [Int64]0
}
#Strings
$Global:PlusLine = "`t[+]"
$Global:ErrorLine = "`t[-]"
$Global:InfoLine = "`t[*]"
$Global:VerboseMode = $VerboseMode.IsPresent

# DCSync replication GUIDs — DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, DS-Replication-Get-Changes-In-Filtered-Set
$script:DCsyncGuids = @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
    '89e95b76-444d-4c62-991a-0facbeda640c'
)

function Write-Good { param( $String ) Write-Host $Global:PlusLine  $String -ForegroundColor 'Green'}
function Write-Bad  { param( $String ) Write-Host $Global:ErrorLine $String -ForegroundColor 'red'  }
function Write-Info { param( $String ) if ($Global:VerboseMode) { Write-Host "$Global:InfoLine $String" -ForegroundColor Cyan } }
function Write-Dbg  { param( $String ) if ($Global:VerboseMode) { Write-Host "`t[DBG] $String" -ForegroundColor DarkYellow } }

function Get-DomainBreachOUSplat {
    if ($Global:TargetOU) { return @{ Path = $Global:TargetOU } }
    return @{}
}

function Invoke-DomainBreachVerboseToggle {
    $Global:VerboseMode = -not $Global:VerboseMode
    $state = if ($Global:VerboseMode) { "ENABLED" } else { "DISABLED" }
    Write-Host "`n`tVerbose/debug output $state" -ForegroundColor $(if ($Global:VerboseMode) { 'Green' } else { 'Yellow' })
    Start-Sleep -Seconds 1
}

function Show-VerboseLabel {
    $status = if ($Global:VerboseMode) { "[ON] " } else { "[OFF]" }
    $color  = if ($Global:VerboseMode) { 'Green' } else { 'Gray' }
    Write-Host "  [V] Toggle Verbose/Debug Output  $status" -ForegroundColor $color
}

function Get-AutoDiscoveredDomain {
    # Try Get-ADDomain first (works when this machine is already a DC)
    try { return (Get-ADDomain -ErrorAction Stop).DNSRoot } catch { Write-Dbg "Get-ADDomain failed: $_" }
    # Fall back to the environment variable (works when domain-joined but not yet a DC)
    if ($env:USERDNSDOMAIN -and $env:USERDNSDOMAIN -ne "") { return $env:USERDNSDOMAIN.ToLower() }
    return ""
}

function Read-DomainName {
    param([string]$Prompt = "`tDomain name")
    $discovered = Get-AutoDiscoveredDomain
    if ($discovered -ne "") {
        $val = Read-Host "$Prompt [$discovered]"
        if ($val -eq "") { return $discovered }
        return $val
    }
    $val = ""
    do { $val = Read-Host "$Prompt (e.g. corp.local)" } until ($val -ne "")
    return $val
}

function Invoke-DomainBreachSMBv1PreCheck {
    param([switch]$Force)
    $feat = Get-WindowsFeature -Name "FS-SMB1" -ErrorAction SilentlyContinue
    if ($feat -and $feat.InstallState -eq "Installed") { return $true }

    Write-Host ""
    Write-Host "`t[!] The FS-SMB1 (SMBv1) Windows feature is not installed." -ForegroundColor Yellow
    Write-Host "`t    Installing it now — a restart is required before" -ForegroundColor Yellow
    Write-Host "`t    vulnerability modules can be enabled." -ForegroundColor Yellow

    $result = Install-WindowsFeature -Name "FS-SMB1" -ErrorAction SilentlyContinue
    if ($result -and $result.Success) {
        Write-Good "FS-SMB1 feature installed successfully."
    } else {
        Write-Bad "FS-SMB1 installation reported a failure — SMBv1 module may not work."
    }

    if ($Force) {
        Write-Host "`t[!] Skipping restart check (-SkipSMBv1Reboot). SMBv1 requires a reboot to fully activate." -ForegroundColor Yellow
        return $true
    }

    Write-Host ""
    Write-Host "`t    Please restart this server, then re-run DomainBreach to enable vulnerabilities." -ForegroundColor Red
    Write-Host "`t    (Pass -SkipSMBv1Reboot to bypass this gate and continue without rebooting.)" -ForegroundColor DarkGray
    Write-Host ""
    $ans = Read-Host "`tPress Enter to exit  |  type FORCE to skip the restart and continue anyway"
    if ($ans.Trim().ToUpper() -eq "FORCE") { return $true }
    return $false
}

function New-RandomPassword {
    param([int]$Length = 12, [int]$NonAlphanumericCount = 2)
    $alpha   = [char[]](48..57) + [char[]](65..90) + [char[]](97..122)
    $special = '!@#$%^&*()_+-='.ToCharArray()
    $all     = $alpha + $special
    do {
        $pass = -join (1..$Length | ForEach-Object {
            $all[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($all.Length)]
        })
    } until (($pass.ToCharArray() | Where-Object { $_ -in $special }).Count -ge $NonAlphanumericCount)
    return $pass
}
function DomainBreach-GetRandom {
   Param(
     [array]$InputList
   )
   return Get-Random -InputObject $InputList
}
function Ensure-DomainBreachOU {
    param(
        [string]$OUName,
        [string]$DomainDN
    )
    $ouDN = "OU=$OUName,$DomainDN"
    try {
        if (Get-ADOrganizationalUnit -Identity $ouDN -ErrorAction SilentlyContinue) {
            Write-Info "Using existing OU: $ouDN"
            $Global:DomainBreachState.OUCreated = $false
        } else {
            New-ADOrganizationalUnit -Name $OUName -Path $DomainDN -ErrorAction Stop
            Write-Good "Created OU: $ouDN"
            $Global:DomainBreachState.OUCreated = $true
        }
        $Global:DomainBreachState.TargetOU = $ouDN
        return $ouDN
    } catch {
        Write-Bad "Failed to create OU '$ouDN': $_ — objects will be created in default containers"
        return ""
    }
}
function DomainBreach-AddADGroup {
    Param(
        [array]$GroupList
    )
    $ou = Get-DomainBreachOUSplat
    foreach ($group in $GroupList) {
        Write-Info "Creating $group Group"
        Try { New-ADGroup -Name $group -GroupScope Global -GroupCategory Security @ou } Catch { Write-Dbg "New-ADGroup '$group' failed: $_" }
        for ($i=1; $i -le (Get-Random -Maximum 20); $i=$i+1 ) {
            $randomuser = (DomainBreach-GetRandom -InputList $Global:CreatedUsers)
            Write-Info "Adding $randomuser to $group"
            Try { Add-ADGroupMember -Identity $group -Members $randomuser } Catch { Write-Dbg "Add-ADGroupMember '$randomuser' to '$group' failed: $_" }
        }
        $Global:AllObjects += $group;
    }
}
function DomainBreach-AddADUser {
    Param(
        [int]$limit = 1
    )
    $ou = Get-DomainBreachOUSplat
    for ($i=1; $i -le $limit; $i=$i+1 ) {
        Write-Progress -Activity "Creating AD Users" -Status "User $i of $limit" -PercentComplete (($i / $limit) * 100)
        $firstname = (DomainBreach-GetRandom -InputList $Global:HumansNames);
        $lastname = (DomainBreach-GetRandom -InputList $Global:HumansNames);
        $SamAccountName = ("{0}.{1}" -f ($firstname, $lastname)).ToLower();
        $principalname = "{0}.{1}" -f ($firstname, $lastname);
        $generated_password = (New-RandomPassword)
        Write-Info "Creating $SamAccountName User"
        $adParams = @{
            Name              = "$firstname $lastname"
            GivenName         = $firstname
            Surname           = $lastname
            SamAccountName    = $SamAccountName
            UserPrincipalName = "$principalname@$Global:Domain"
            AccountPassword   = (ConvertTo-SecureString $generated_password -AsPlainText -Force)
            Enabled           = $true
        } + $ou
        try {
            New-ADUser @adParams
            $Global:CreatedUsers += $SamAccountName
        } catch {
            Write-Dbg "New-ADUser '$SamAccountName' failed: $_"
            if (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue) {
                $Global:CreatedUsers += $SamAccountName
            }
        }
    }
    Write-Progress -Activity "Creating AD Users" -Completed
}
function DomainBreach-AddACL {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Destination,

            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [System.Security.Principal.IdentityReference]$Source,

            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Rights

        )
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
        $type = [System.Security.AccessControl.AccessControlType]"Allow"
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Source,$adRights,$type,$inheritanceType
        $acl = Get-Acl -Path ("AD:" + $Destination)
        $acl.AddAccessRule($ACE)
        Set-Acl -Path ("AD:" + $Destination) -AclObject $acl
        $Global:DomainBreachState.BadACLs += @{ Source = $Source.Value; Destination = $Destination; Rights = $Rights }
}
function DomainBreach-BadAcls {
    foreach ($abuse in $Global:BadACL) {
        $ngroup = DomainBreach-GetRandom -InputList $Global:NormalGroups
        $mgroup = DomainBreach-GetRandom -InputList $Global:MidGroups
        $DstGroup = Get-ADGroup -Identity $mgroup
        $SrcGroup = Get-ADGroup -Identity $ngroup
        DomainBreach-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Info "BadACL $abuse $ngroup to $mgroup"
    }
    foreach ($abuse in $Global:BadACL) {
        $hgroup = DomainBreach-GetRandom -InputList $Global:HighGroups
        $mgroup = DomainBreach-GetRandom -InputList $Global:MidGroups
        $DstGroup = Get-ADGroup -Identity $hgroup
        $SrcGroup = Get-ADGroup -Identity $mgroup
        DomainBreach-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Info "BadACL $abuse $mgroup to $hgroup"
    }
    for ($i=1; $i -le (Get-Random -Maximum 25); $i=$i+1 ) {
        $abuse = (DomainBreach-GetRandom -InputList $Global:BadACL);
        $randomuser = DomainBreach-GetRandom -InputList $Global:CreatedUsers
        $randomgroup = DomainBreach-GetRandom -InputList $Global:AllObjects
        if ((Get-Random -Maximum 2)){
            $Dstobj = Get-ADUser -Identity $randomuser
            $Srcobj = Get-ADGroup -Identity $randomgroup
        }else{
            $Srcobj = Get-ADUser -Identity $randomuser
            $Dstobj = Get-ADGroup -Identity $randomgroup
        }
        DomainBreach-AddACL -Source $Srcobj.sid -Destination $Dstobj.DistinguishedName -Rights $abuse 
        Write-Info "BadACL $abuse $randomuser and $randomgroup"
    }
}
function DomainBreach-Kerberoasting {
    $ou = Get-DomainBreachOUSplat
    $selected_service = (DomainBreach-GetRandom -InputList $Global:ServicesAccountsAndSPNs)
    $svc = $selected_service.split(',')[0];
    $spn = $selected_service.split(',')[1];
    $password = DomainBreach-GetRandom -InputList $Global:BadPasswords;
    Write-Info "Kerberoasting $svc $spn"
    $msaParams = @{
        Name                    = $svc
        ServicePrincipalNames   = "$svc/$spn.$Global:Domain"
        AccountPassword         = (ConvertTo-SecureString $password -AsPlainText -Force)
        RestrictToSingleComputer = $true
        PassThru                = $true
    } + $ou
    try { New-ADServiceAccount @msaParams; $Global:DomainBreachState.ServiceAccounts += $svc } catch { Write-Dbg "New-ADServiceAccount '$svc' failed: $_" }
    foreach ($sv in $Global:ServicesAccountsAndSPNs) {
        if ($selected_service -ne $sv) {
            $svc = $sv.split(',')[0];
            $spn = $sv.split(',')[1];
            Write-Info "Creating $svc services account"
            $password = (New-RandomPassword)
            $msaParams = @{
                Name                    = $svc
                ServicePrincipalNames   = "$svc/$spn.$Global:Domain"
                AccountPassword         = (ConvertTo-SecureString $password -AsPlainText -Force)
                RestrictToSingleComputer = $true
                PassThru                = $true
            } + $ou
            try { New-ADServiceAccount @msaParams; $Global:DomainBreachState.ServiceAccounts += $svc } catch { Write-Dbg "New-ADServiceAccount '$svc' failed: $_" }

        }
    }
}
function DomainBreach-ASREPRoasting {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $randomuser = (DomainBreach-GetRandom -InputList $Global:CreatedUsers)
        $password = DomainBreach-GetRandom -InputList $Global:BadPasswords;
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADAccountControl -Identity $randomuser -DoesNotRequirePreAuth 1
        if ($randomuser -notin $Global:DomainBreachState.ASREPUsers) { $Global:DomainBreachState.ASREPUsers += $randomuser }
        Write-Info "AS-REPRoasting $randomuser"
    }
}
function DomainBreach-DnsAdmins {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $randomuser = (DomainBreach-GetRandom -InputList $Global:CreatedUsers)
        Add-ADGroupMember -Identity "DnsAdmins" -Members $randomuser
        if ($randomuser -notin $Global:DomainBreachState.DnsAdminsUsers) { $Global:DomainBreachState.DnsAdminsUsers += $randomuser }
        Write-Info "DnsAdmins : $randomuser"
    }
    $randomg = (DomainBreach-GetRandom -InputList $Global:MidGroups)
    Add-ADGroupMember -Identity "DnsAdmins" -Members $randomg
    $Global:DomainBreachState.DnsAdminsGroups += $randomg
    Write-Info "DnsAdmins Nested Group : $randomg"
}
function DomainBreach-PwdInObjectDescription {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $randomuser = (DomainBreach-GetRandom -InputList $Global:CreatedUsers)
        $password = (New-RandomPassword)
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "User Password $password"
        Write-Info "Password in Description : $randomuser"
    }
}
function DomainBreach-DefaultPassword {
    for ($i=1; $i -le (Get-Random -Maximum 5); $i=$i+1 ) {
        $randomuser = (DomainBreach-GetRandom -InputList $Global:CreatedUsers)
        $password = "Changeme123!";
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "New User ,DefaultPassword"
        Set-ADUser $randomuser -ChangePasswordAtLogon $true
        Write-Info "Default Password : $randomuser"
    }
}
function DomainBreach-PasswordSpraying {
    $same_password = "ncc1701";
    for ($i=1; $i -le (Get-Random -Maximum 12); $i=$i+1 ) {
        $randomuser = (DomainBreach-GetRandom -InputList $Global:CreatedUsers)
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $same_password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "Shared User"
        Write-Info "Same Password (Password Spraying) : $randomuser"
    }
}
function DomainBreach-DCSync {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $domainDN = (Get-ADDomain $Global:Domain).DistinguishedName
        $randomuser = (DomainBreach-GetRandom -InputList $Global:CreatedUsers)
        $sid = (Get-ADUser -Identity $randomuser).sid
        $acl = Get-Acl -Path ("AD:" + $domainDN)

        foreach ($guidStr in $script:DCsyncGuids) {
            $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',([Guid]$guidStr))
            $acl.AddAccessRule($ACEGetChanges)
        }
        Set-Acl -Path ("AD:" + $domainDN) -AclObject $acl
        if ($randomuser -notin $Global:DomainBreachState.DCsyncUsers) { $Global:DomainBreachState.DCsyncUsers += $randomuser }

        Set-ADUser $randomuser -Description "Replication Account"
        Write-Info "Giving DCSync to : $randomuser"
    }
}
function DomainBreach-DisableSMBSigning {
    Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Force
}
function DomainBreach-KrbtgtPwdAge {
    # A-Krbtgt: Simulate a stale KRBTGT password by backdating pwdLastSet to 5 years ago
    # PingCastle scoring: 50 pts at 4+ years, 40 pts at 3+, 30 pts at 2+, 20 pts at 1+ year
    Try {
        $targetDate = (Get-Date).AddYears(-5)
        $fileTime   = $targetDate.ToFileTimeUtc()
        $krbtgtDN   = (Get-ADUser -Identity "krbtgt").DistinguishedName
        # Use psbase.Properties to properly marshal the Large Integer COM type
        $de         = [ADSI]"LDAP://$krbtgtDN"
        $de.psbase.Properties["pwdLastSet"].Value = $fileTime
        $de.psbase.CommitChanges()
        $Global:DomainBreachState.KrbtgtPwdLastSetModified = $true
        $Global:DomainBreachState.KrbtgtOrigPwdLastSet     = $fileTime
        Write-Info "KRBTGT pwdLastSet set to $($targetDate.ToString('yyyy-MM-dd')) (5 years ago)"
    } Catch {
        # Fallback: try via Set-ADObject (bypasses Set-ADUser attribute restrictions)
        Try {
            $targetDate = (Get-Date).AddYears(-5)
            $fileTime   = [System.Int64]$targetDate.ToFileTimeUtc()
            $krbtgtDN   = (Get-ADUser -Identity "krbtgt").DistinguishedName
            Set-ADObject -Identity $krbtgtDN -Replace @{ pwdLastSet = $fileTime } -ErrorAction Stop
            $Global:DomainBreachState.KrbtgtPwdLastSetModified = $true
            $Global:DomainBreachState.KrbtgtOrigPwdLastSet     = $fileTime
            Write-Info "KRBTGT pwdLastSet backdated (fallback method)"
        } Catch { Write-Bad "Failed to modify KRBTGT pwdLastSet: $_" }
    }
}
function DomainBreach-UnconstrainedDelegation {
    # A-UnconstrainedDelegation, P-UnconstrainedDelegation
    for ($i=1; $i -le (Get-Random -Minimum 1 -Maximum 4); $i++) {
        $u = DomainBreach-GetRandom -InputList $Global:CreatedUsers
        Try {
            Set-ADUser -Identity $u -TrustedForDelegation $true -ErrorAction Stop
            if ($u -notin $Global:DomainBreachState.UnconstrainedDelegationUsers) {
                $Global:DomainBreachState.UnconstrainedDelegationUsers += $u
            }
            Write-Info "Unconstrained Delegation (user): $u"
        } Catch { Write-Bad "Failed to set unconstrained delegation on ${u}: $_" }
    }
    $ou = Get-DomainBreachOUSplat
    Try {
        $compName = "SVC-HOST-$(Get-Random -Minimum 100 -Maximum 999)"
        New-ADComputer -Name $compName -Enabled $true -TrustedForDelegation $true -ErrorAction Stop @ou
        $Global:DomainBreachState.UnconstrainedDelegationComputers += $compName
        Write-Info "Unconstrained Delegation (computer): $compName"
    } Catch { Write-Bad "Failed to create delegated computer: $_" }
}
function DomainBreach-SchemaAdminAndPrivKerberoast {
    # P-SchemaAdmin: non-empty Schema Admins group
    # P-ServiceDomainAdmin + P-Kerberoasting: Domain Admin service account with SPN
    $schemaUser = DomainBreach-GetRandom -InputList $Global:CreatedUsers
    Try {
        Add-ADGroupMember -Identity "Schema Admins" -Members $schemaUser -ErrorAction Stop
        $Global:DomainBreachState.SchemaAdminUsers += $schemaUser
        Write-Info "Schema Admins member: $schemaUser"
    } Catch { Write-Bad "Failed to add $schemaUser to Schema Admins: $_" }

    $privSvcName = "da_svc_sql"
    $privSvcPwd  = DomainBreach-GetRandom -InputList $Global:BadPasswords
    $ou = Get-DomainBreachOUSplat
    Try {
        New-ADUser -Name $privSvcName -SamAccountName $privSvcName `
                   -UserPrincipalName "$privSvcName@$Global:Domain" `
                   -AccountPassword (ConvertTo-SecureString $privSvcPwd -AsPlainText -Force) `
                   -Enabled $true -ErrorAction Stop @ou
        Set-ADUser -Identity $privSvcName -Add @{ servicePrincipalName = "MSSQLSvc/sqlserver.$($Global:Domain):1433" }
        Add-ADGroupMember -Identity "Domain Admins" -Members $privSvcName
        $Global:DomainBreachState.PrivilegedKerberoastUsers += $privSvcName
        Write-Info "Privileged Kerberoast / ServiceDomainAdmin: $privSvcName"
    } Catch { Write-Bad "Failed to create privileged service account: $_" }
}
function DomainBreach-GuestAndPreWin2000 {
    # A-Guest: Enable the built-in Guest account
    Try {
        Enable-ADAccount -Identity "Guest" -ErrorAction Stop
        $Global:DomainBreachState.GuestEnabled = $true
        Write-Info "Guest account enabled"
    } Catch { Write-Bad "Failed to enable Guest account: $_" }

    # A-PreWin2000AuthenticatedUsers: Add Authenticated Users (S-1-5-11) to Pre-Windows 2000 Compatible Access
    # Use net.exe because "Authenticated Users" is a well-known SID not stored as a ForeignSecurityPrincipal object
    Try {
        $result = & net.exe localgroup "Pre-Windows 2000 Compatible Access" "Authenticated Users" /add 2>&1
        $resultStr = $result -join " "
        if ($LASTEXITCODE -ne 0 -and ($resultStr -notmatch "already in|already a member")) {
            throw $resultStr
        }
        $Global:DomainBreachState.PreWin2000AuthUsers = $true
        Write-Info "Authenticated Users added to Pre-Windows 2000 Compatible Access"
    } Catch { Write-Bad "Failed to add Authenticated Users to Pre-Windows 2000 Compatible Access: $_" }
}
function DomainBreach-ReversibleAndDESEncryption {
    # A-ReversiblePwd / S-ReversibleEncryption: reversible password storage
    for ($i=1; $i -le (Get-Random -Minimum 1 -Maximum 5); $i++) {
        $u = DomainBreach-GetRandom -InputList $Global:CreatedUsers
        Try {
            Set-ADUser -Identity $u -AllowReversiblePasswordEncryption $true -ErrorAction Stop
            if ($u -notin $Global:DomainBreachState.ReversibleEncryptionUsers) { $Global:DomainBreachState.ReversibleEncryptionUsers += $u }
            Write-Info "Reversible encryption enabled: $u"
        } Catch { Write-Bad "Failed to enable reversible encryption on ${u}: $_" }
    }
    # S-DesEnabled: DES Kerberos encryption type on accounts
    for ($i=1; $i -le (Get-Random -Minimum 1 -Maximum 4); $i++) {
        $u = DomainBreach-GetRandom -InputList $Global:CreatedUsers
        Try {
            Set-ADUser -Identity $u -KerberosEncryptionType DES -ErrorAction Stop
            if ($u -notin $Global:DomainBreachState.DesEncryptionUsers) { $Global:DomainBreachState.DesEncryptionUsers += $u }
            Write-Info "DES encryption enabled: $u"
        } Catch { Write-Bad "Failed to enable DES encryption on ${u}: $_" }
    }
}
function DomainBreach-PasswordNeverExpires {
    # S-PwdNeverExpires: accounts with passwords that never expire
    for ($i=1; $i -le (Get-Random -Minimum 5 -Maximum 15); $i++) {
        $u = DomainBreach-GetRandom -InputList $Global:CreatedUsers
        Try {
            Set-ADUser -Identity $u -PasswordNeverExpires $true -ErrorAction Stop
            if ($u -notin $Global:DomainBreachState.PasswordNeverExpiresUsers) { $Global:DomainBreachState.PasswordNeverExpiresUsers += $u }
            Write-Info "PasswordNeverExpires: $u"
        } Catch { Write-Bad "Failed to set PasswordNeverExpires on ${u}: $_" }
    }
}
function DomainBreach-LegacyProtocols {
    # A-LMHashAuthorized: Enable LM hash storage (NoLMHash=0)
    Try {
        $lmKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $orig  = (Get-ItemProperty -Path $lmKey -Name "NoLMHash" -ErrorAction SilentlyContinue).NoLMHash
        $Global:DomainBreachState.OrigLMHash = if ($null -eq $orig) { 1 } else { $orig }
        Set-ItemProperty -Path $lmKey -Name "NoLMHash" -Value 0 -Type DWord -Force
        $Global:DomainBreachState.LMHashEnabled = $true
        Write-Info "LM Hash storage enabled (NoLMHash=0)"
    } Catch { Write-Bad "Failed to enable LM Hash storage: $_" }

    # A-NullSession: Allow null sessions
    Try {
        $lmsKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        $origNS = (Get-ItemProperty -Path $lmsKey -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue).RestrictNullSessAccess
        $Global:DomainBreachState.OrigNullSession = if ($null -eq $origNS) { 1 } else { $origNS }
        Set-ItemProperty -Path $lmsKey -Name "RestrictNullSessAccess" -Value 0 -Type DWord -Force
        $Global:DomainBreachState.NullSessionEnabled = $true
        Write-Info "Null sessions enabled (RestrictNullSessAccess=0)"
    } Catch { Write-Bad "Failed to enable null sessions: $_" }

    # S-SMBv1: Enable SMBv1 server protocol
    Try {
        # On modern Windows Server, SMBv1 may be completely absent — install the feature first
        $smb1Feat = Get-WindowsFeature -Name "FS-SMB1" -ErrorAction SilentlyContinue
        $needsRestart = $false
        if ($smb1Feat -and $smb1Feat.InstallState -ne "Installed") {
            $installResult = Install-WindowsFeature -Name "FS-SMB1" -ErrorAction SilentlyContinue
            $needsRestart  = $installResult -and $installResult.RestartNeeded -ne "No"
        }
        $origSMB = $false
        Try { $origSMB = (Get-SmbServerConfiguration).EnableSMB1Protocol } Catch { Write-Dbg "Get-SmbServerConfiguration failed: $_" }
        $Global:DomainBreachState.OrigSMBv1Enabled = [bool]$origSMB
        if ($needsRestart) {
            # Service not yet loaded; enable via registry (takes effect after reboot)
            $lmsParams = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            Set-ItemProperty -Path $lmsParams -Name "SMB1" -Value 1 -Type DWord -Force
            Write-Info "SMBv1 enabled via registry (restart already pending to load FS-SMB1 driver)"
        } else {
            Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
            Write-Info "SMBv1 enabled"
        }
        $Global:DomainBreachState.SMBv1Enabled = $true
    } Catch { Write-Bad "Failed to enable SMBv1: $_" }
}
function DomainBreach-LDAPSigningAndSpooler {
    # A-LDAPSigningDisabled / A-DCLdapSign: Disable LDAP server integrity
    # 0=None, 1=Negotiate signing, 2=Require signing
    Try {
        $ldapKey  = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $origLDAP = (Get-ItemProperty -Path $ldapKey -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
        $Global:DomainBreachState.OrigLDAPSigning = if ($null -eq $origLDAP) { 2 } else { $origLDAP }
        Set-ItemProperty -Path $ldapKey -Name "LDAPServerIntegrity" -Value 0 -Type DWord -Force
        $Global:DomainBreachState.LDAPSigningDisabled = $true
        Write-Info "LDAP server signing disabled (LDAPServerIntegrity=0)"
    } Catch { Write-Bad "Failed to disable LDAP signing: $_" }

    # A-DCSpooler: Ensure Print Spooler is running on the DC
    Try {
        $spooler = Get-Service -Name Spooler -ErrorAction Stop
        $Global:DomainBreachState.OrigSpoolerStartType = $spooler.StartType.ToString()
        Set-Service -Name Spooler -StartupType Automatic -ErrorAction Stop
        Start-Service -Name Spooler -ErrorAction Stop
        $Global:DomainBreachState.SpoolerRunning = $true
        Write-Info "Print Spooler started and set to Automatic"
    } Catch { Write-Bad "Failed to start Print Spooler: $_" }
}
function DomainBreach-AdminSDHolderAbuse {
    # A-AdminSDHolder: Grant GenericAll on AdminSDHolder to a random unprivileged user
    # AdminSDHolder ACEs propagate to all protected accounts every 60 min via SDProp
    $u = DomainBreach-GetRandom -InputList $Global:CreatedUsers
    Try {
        $domainDN  = (Get-ADDomain $Global:Domain).DistinguishedName
        $asdDN     = "CN=AdminSDHolder,CN=System,$domainDN"
        $userSid   = (Get-ADUser -Identity $u).SID
        $acl       = Get-Acl -Path ("AD:" + $asdDN)
        $adRights  = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
        $type      = [System.Security.AccessControl.AccessControlType]"Allow"
        $inherit   = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
        $ACE       = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $userSid,$adRights,$type,$inherit
        $acl.AddAccessRule($ACE)
        Set-Acl -Path ("AD:" + $asdDN) -AclObject $acl
        $Global:DomainBreachState.BadACLs += @{ Source = $userSid.Value; Destination = $asdDN; Rights = "GenericAll" }
        Write-Info "AdminSDHolder GenericAll granted to: $u"
    } Catch { Write-Bad "Failed to modify AdminSDHolder ACL: $_" }
}
function DomainBreach-SIDHistory {
    # S-SIDHistory: Add SID history to user accounts via DsAddSidHistory API
    # Direct LDAP writes to sIDHistory are blocked by AD; the DS API is required.
    # We do a within-domain SID copy (src user's SID -> dst user's sIDHistory),
    # which PingCastle's S-SIDHistory check still flags.

    if (-not ([System.Management.Automation.PSTypeName]'DsApiHelper').Type) {
        Try {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class DsApiHelper {
    [DllImport("ntdsapi.dll", CharSet = CharSet.Unicode)]
    public static extern uint DsBind(string DomainControllerName, string DnsDomainName, out IntPtr phDS);
    [DllImport("ntdsapi.dll")]
    public static extern uint DsUnBind(ref IntPtr phDS);
    [DllImport("ntdsapi.dll", CharSet = CharSet.Unicode)]
    public static extern uint DsAddSidHistory(IntPtr hDS, uint Flags, string SrcDomain, string SrcPrincipal,
        string SrcDomainController, IntPtr SrcDomainCreds, string DstDomain, string DstPrincipal);
}
'@ -ErrorAction Stop
        } Catch { Write-Bad "Failed to load DsAddSidHistory API: $_"; return }
    }

    # Enable same-domain SID history additions (required by DC)
    $ntdsKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $origAllow = (Get-ItemProperty $ntdsKey -Name "Allow SID History Additions" -ErrorAction SilentlyContinue)."Allow SID History Additions"
    Set-ItemProperty $ntdsKey -Name "Allow SID History Additions" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

    # DsAddSidHistory for same-domain operations requires audit account management (success) to be enabled
    # Without it the API returns ERROR_INVALID_PARAMETER (87)
    & auditpol.exe /set /subcategory:"User Account Management" /success:enable 2>&1 | Out-Null

    $domainNB  = (Get-ADDomain).NetBIOSName
    $domainDNS = (Get-ADDomain).DNSRoot
    $hDS = [IntPtr]::Zero

    Try {
        $bindRet = [DsApiHelper]::DsBind($null, $domainDNS, [ref]$hDS)
        if ($bindRet -ne 0) { throw "DsBind failed with error code $bindRet" }

        for ($i = 1; $i -le (Get-Random -Minimum 1 -Maximum 4); $i++) {
            $dst = DomainBreach-GetRandom -InputList $Global:CreatedUsers
            # Use a different created user as the SID source (same-domain copy triggers PingCastle S-SIDHistory)
            $src = $Global:CreatedUsers | Where-Object { $_ -ne $dst } | Select-Object -First 1
            if (-not $src) { $src = "Administrator" }
            Try {
                $ret = [DsApiHelper]::DsAddSidHistory($hDS, 0, $domainNB, $src, $null, [IntPtr]::Zero, $domainNB, $dst)
                if ($ret -eq 0) {
                    if ($dst -notin $Global:DomainBreachState.SIDHistoryUsers) { $Global:DomainBreachState.SIDHistoryUsers += $dst }
                    Write-Info "SID History added to: $dst (source: $src)"
                } else {
                    Write-Bad "Failed to add SID History to ${dst}: DsAddSidHistory error code $ret"
                }
            } Catch { Write-Bad "Failed to add SID History to ${dst}: $_" }
        }
    } Catch { Write-Bad "Failed to add SID History: $_"
    } Finally {
        if ($hDS -ne [IntPtr]::Zero) { [DsApiHelper]::DsUnBind([ref]$hDS) }
        # Restore registry key
        if ($null -eq $origAllow) {
            Remove-ItemProperty $ntdsKey -Name "Allow SID History Additions" -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty $ntdsKey -Name "Allow SID History Additions" -Value $origAllow -Type DWord -Force -ErrorAction SilentlyContinue
        }
    }
}
function DomainBreach-RemoveACL {
    param(
        [string]$Destination,
        [string]$SourceSid,
        [string]$Rights
    )
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SourceSid)
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
        $type = [System.Security.AccessControl.AccessControlType]"Allow"
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid,$adRights,$type,$inheritanceType
        $acl = Get-Acl -Path ("AD:" + $Destination)
        $acl.RemoveAccessRule($ACE) | Out-Null
        Set-Acl -Path ("AD:" + $Destination) -AclObject $acl
    } catch {
        Write-Bad "Failed to remove ACL ($Rights on $Destination): $_"
    }
}
function DomainBreach-SaveState {
    param([string]$Path)
    $Global:DomainBreachState | ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8
    Write-Good "State saved to $Path"
}
function Invoke-DomainBreach-Rollback {
    param(
        [Parameter(Mandatory=$true)]
        [string]$StateFile
    )
    if (-not (Test-Path $StateFile)) {
        Write-Bad "State file not found: $StateFile"
        return
    }
    $state = Get-Content $StateFile -Raw | ConvertFrom-Json
    $Global:Domain = $state.Domain
    Write-Good "Starting rollback for domain: $Global:Domain"

    # Remove DCSync extended rights
    foreach ($user in $state.DCsyncUsers) {
        try {
            $userObj = Get-ADUser -Identity $user -ErrorAction SilentlyContinue
            if (-not $userObj) { continue }
            $sid = $userObj.sid
            $domainDN = (Get-ADDomain $Global:Domain).DistinguishedName
            $acl = Get-Acl -Path ("AD:" + $domainDN)
            foreach ($guidStr in $script:DCsyncGuids) {
                $ACE = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',([Guid]$guidStr))
                $acl.RemoveAccessRule($ACE) | Out-Null
            }
            Set-Acl -Path ("AD:" + $domainDN) -AclObject $acl
            Write-Good "Removed DCSync from $user"
        } catch { Write-Bad "Failed to remove DCSync from ${user}: $_" }
    }

    # Remove bad ACLs
    foreach ($entry in $state.BadACLs) {
        DomainBreach-RemoveACL -Destination $entry.Destination -SourceSid $entry.Source -Rights $entry.Rights
    }
    Write-Good "Bad ACLs removed"

    # Remove DnsAdmins memberships
    foreach ($user in $state.DnsAdminsUsers) {
        try { Remove-ADGroupMember -Identity "DnsAdmins" -Members $user -Confirm:$false } catch { Write-Bad "Failed to remove $user from DnsAdmins: $_" }
    }
    foreach ($grp in $state.DnsAdminsGroups) {
        try { Remove-ADGroupMember -Identity "DnsAdmins" -Members $grp -Confirm:$false } catch { Write-Bad "Failed to remove group $grp from DnsAdmins: $_" }
    }
    Write-Good "DnsAdmins memberships removed"

    # Re-enable Kerberos pre-authentication
    foreach ($user in $state.ASREPUsers) {
        try { Set-ADAccountControl -Identity $user -DoesNotRequirePreAuth 0 } catch { Write-Bad "Failed to re-enable pre-auth on ${user}: $_" }
    }
    Write-Good "Kerberos pre-auth restored"

    # Remove service accounts
    foreach ($svc in $state.ServiceAccounts) {
        try { Remove-ADServiceAccount -Identity $svc -Confirm:$false } catch { Write-Bad "Failed to remove service account ${svc}: $_" }
    }
    Write-Good "Service accounts removed"

    # Remove users
    foreach ($user in $state.Users) {
        try { Remove-ADUser -Identity $user -Confirm:$false } catch { Write-Bad "Failed to remove user ${user}: $_" }
    }
    Write-Good "Users removed"

    # Remove groups
    foreach ($grp in $state.Groups) {
        try { Remove-ADGroup -Identity $grp -Confirm:$false } catch { Write-Bad "Failed to remove group ${grp}: $_" }
    }
    Write-Good "Groups removed"

    # Restore password policy
    try {
        $pp = $state.PasswordPolicy
        Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain `
            -LockoutDuration ([TimeSpan]::Parse($pp.LockoutDuration)) `
            -LockoutObservationWindow ([TimeSpan]::Parse($pp.LockoutObservationWindow)) `
            -ComplexityEnabled $pp.ComplexityEnabled `
            -ReversibleEncryptionEnabled $pp.ReversibleEncryptionEnabled `
            -MinPasswordLength $pp.MinPasswordLength
        Write-Good "Password policy restored"
    } catch { Write-Bad "Failed to restore password policy: $_" }

    # Restore SMB signing
    try {
        Set-SmbClientConfiguration -RequireSecuritySignature $state.SMBSigningRequired -EnableSecuritySignature $state.SMBSigningEnabled -Force
        Write-Good "SMB signing configuration restored"
    } catch { Write-Bad "Failed to restore SMB signing: $_" }

    # Restore KRBTGT password age (reset password resets pwdLastSet to now)
    if ($state.KrbtgtPwdLastSetModified) {
        try {
            $newPwd = New-RandomPassword -Length 32 -NonAlphanumericCount 4
            Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (ConvertTo-SecureString $newPwd -AsPlainText -Force)
            Write-Good "KRBTGT password reset (pwdLastSet restored to current time)"
        } catch { Write-Bad "Failed to reset KRBTGT password: $_" }
    }

    # Remove unconstrained delegation
    foreach ($u in $state.UnconstrainedDelegationUsers) {
        try { Set-ADUser -Identity $u -TrustedForDelegation $false } catch { Write-Bad "Failed to remove delegation from ${u}: $_" }
    }
    foreach ($comp in $state.UnconstrainedDelegationComputers) {
        try { Remove-ADComputer -Identity $comp -Confirm:$false } catch { Write-Bad "Failed to remove computer ${comp}: $_" }
    }
    Write-Good "Unconstrained delegation removed"

    # Remove Schema Admins memberships and privileged service accounts
    foreach ($u in $state.SchemaAdminUsers) {
        try { Remove-ADGroupMember -Identity "Schema Admins" -Members $u -Confirm:$false } catch { Write-Bad "Failed to remove $u from Schema Admins: $_" }
    }
    foreach ($u in $state.PrivilegedKerberoastUsers) {
        try {
            Remove-ADGroupMember -Identity "Domain Admins" -Members $u -Confirm:$false -ErrorAction SilentlyContinue
            Remove-ADUser -Identity $u -Confirm:$false
        } catch { Write-Bad "Failed to remove privileged svc account ${u}: $_" }
    }
    Write-Good "Schema Admins and privileged service accounts removed"

    # Disable Guest and restore Pre-Windows 2000 Compatible Access group
    if ($state.GuestEnabled) {
        try { Disable-ADAccount -Identity "Guest" } catch { Write-Bad "Failed to disable Guest: $_" }
        Write-Good "Guest account disabled"
    }
    if ($state.PreWin2000AuthUsers) {
        try {
            & net.exe localgroup "Pre-Windows 2000 Compatible Access" "Authenticated Users" /delete 2>&1 | Out-Null
            Write-Good "Pre-Windows 2000 Compatible Access restored"
        } catch { Write-Bad "Failed to remove Authenticated Users from Pre-Windows 2000 Compatible Access: $_" }
    }

    # Restore reversible encryption and DES settings
    foreach ($u in $state.ReversibleEncryptionUsers) {
        try { Set-ADUser -Identity $u -AllowReversiblePasswordEncryption $false } catch { Write-Bad "Failed to disable reversible encryption on ${u}: $_" }
    }
    foreach ($u in $state.DesEncryptionUsers) {
        try { Set-ADUser -Identity $u -KerberosEncryptionType RC4,AES128,AES256 } catch { Write-Bad "Failed to restore encryption types on ${u}: $_" }
    }
    Write-Good "Reversible and DES encryption settings restored"

    # Restore PasswordNeverExpires
    foreach ($u in $state.PasswordNeverExpiresUsers) {
        try { Set-ADUser -Identity $u -PasswordNeverExpires $false } catch { Write-Bad "Failed to re-enable password expiry on ${u}: $_" }
    }
    Write-Good "PasswordNeverExpires restored"

    # Restore legacy protocol settings
    if ($state.LMHashEnabled) {
        try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value $state.OrigLMHash -Type DWord -Force } catch { Write-Bad "Failed to restore LM Hash setting: $_" }
        Write-Good "LM Hash setting restored"
    }
    if ($state.NullSessionEnabled) {
        try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value $state.OrigNullSession -Type DWord -Force } catch { Write-Bad "Failed to restore null session setting: $_" }
        Write-Good "Null session setting restored"
    }
    if ($state.SMBv1Enabled) {
        try { Set-SmbServerConfiguration -EnableSMB1Protocol $state.OrigSMBv1Enabled -Force } catch { Write-Bad "Failed to restore SMBv1: $_" }
        Write-Good "SMBv1 setting restored"
    }

    # Restore LDAP signing and Print Spooler
    if ($state.LDAPSigningDisabled) {
        try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value $state.OrigLDAPSigning -Type DWord -Force } catch { Write-Bad "Failed to restore LDAP signing: $_" }
        Write-Good "LDAP signing setting restored"
    }
    if ($state.SpoolerRunning) {
        try {
            $origStart = if ($state.OrigSpoolerStartType -eq "" -or $null -eq $state.OrigSpoolerStartType) { "Disabled" } else { $state.OrigSpoolerStartType }
            Set-Service -Name Spooler -StartupType $origStart -ErrorAction SilentlyContinue
            if ($origStart -eq "Disabled") { Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue }
        } catch { Write-Bad "Failed to restore Spooler state: $_" }
        Write-Good "Print Spooler service restored"
    }

    # Clear SID History (enable same reg key so the LDAP clear is permitted)
    $ntdsKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    Set-ItemProperty $ntdsKey -Name "Allow SID History Additions" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    foreach ($u in $state.SIDHistoryUsers) {
        try { Set-ADUser -Identity $u -Clear sIDHistory } catch { Write-Bad "Failed to clear SID History from ${u}: $_" }
    }
    Remove-ItemProperty $ntdsKey -Name "Allow SID History Additions" -ErrorAction SilentlyContinue
    Write-Good "SID History cleared"

    # Remove the DomainBreach OU if it was created by this run
    if ($state.OUCreated -and $state.TargetOU -ne "") {
        try {
            Set-ADOrganizationalUnit -Identity $state.TargetOU -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
            Remove-ADOrganizationalUnit -Identity $state.TargetOU -Recursive -Confirm:$false
            Write-Good "Removed OU: $($state.TargetOU)"
        } catch { Write-Bad "Failed to remove OU '$($state.TargetOU)': $_" }
    }

    Write-Good "Rollback complete"
}
function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
}
function Test-IsDomainController {
    return ((Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole -ge 4)
}
function Test-ADDSRoleInstalled {
    # ServerManager is Windows PowerShell-only; skip it in PS7+ to avoid WinPSCompatSession warning.
    # The fallbacks below are sufficient for detection in all versions.
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        try {
            Import-Module ServerManager -ErrorAction Stop
            $feature = Get-WindowsFeature AD-Domain-Services -ErrorAction Stop
            if ($feature.Installed) { return $true }
        } catch { Write-Dbg "ServerManager AD-Domain-Services check failed: $_" }
    }
    # Fallback: ADDSDeployment module is only present when the AD DS role is installed.
    # PS7 does not search the Windows PowerShell module path, so check by file path as well.
    if (Get-Module -ListAvailable -Name ADDSDeployment -ErrorAction SilentlyContinue) { return $true }
    $wpsModulePath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\ADDSDeployment\ADDSDeployment.psd1"
    if (Test-Path $wpsModulePath) { return $true }
    # Fallback: NTDS service exists once the role is installed and DC is promoted
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) { return $true }
    return $false
}
function Invoke-DomainBreachPrerequisiteCheck {
    Write-Host ""
    Write-Host "`t--- Prerequisite Check ---" -ForegroundColor Cyan

    if (Test-IsAdmin) { Write-Good "Running as Administrator" }
    else              { Write-Bad  "Not running as Administrator" }

    if (Test-ADDSRoleInstalled) { Write-Good "AD-Domain-Services role is installed" }
    else                        { Write-Bad  "AD-Domain-Services role is NOT installed (use option [2])" }

    if (Test-IsDomainController) {
        Write-Good "This machine is a Domain Controller"
        try {
            $d = Get-ADDomain -ErrorAction Stop
            Write-Good "Domain: $($d.DNSRoot)  |  NetBIOS: $($d.NetBIOSName)"
        } catch { Write-Bad "AD DS role present but domain not yet accessible" }
    } else {
        Write-Bad "This machine is NOT a Domain Controller (use option [3])"
    }

    $dhcp = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.Dhcp -eq 'Enabled' -and $_.InterfaceAlias -notlike '*Loopback*' }
    if ($dhcp) { Write-Bad "DHCP detected on: $($dhcp.InterfaceAlias -join ', ') � static IP recommended for DCs" }
    else       { Write-Good "Static IP configured" }

    $addsModPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\ADDSDeployment\ADDSDeployment.psd1"
    if ((Get-Module -ListAvailable -Name ADDSDeployment -ErrorAction SilentlyContinue) -or (Test-Path $addsModPath)) {
        Write-Good "ADDSDeployment module available"
    } else { Write-Bad "ADDSDeployment module not available (install AD DS role first)" }

    Read-Host "`n`tPress Enter to continue"
}
function Invoke-DomainBreachRoleInstall {
    Write-Host ""
    if (Test-ADDSRoleInstalled) {
        Write-Good "AD-Domain-Services role is already installed"
        Read-Host "`t`tPress Enter to continue"
        return
    }
    if (-not (Test-IsAdmin)) {
        Write-Bad "Must run as Administrator to install Windows features"
        Read-Host "`t`tPress Enter to continue"
        return
    }
    Write-Host "`t[*] Installing AD-Domain-Services, DNS, and management tools..." -ForegroundColor Yellow
    try {
        $result = Install-WindowsFeature -Name AD-Domain-Services,DNS -IncludeManagementTools -Verbose:$false -WarningAction SilentlyContinue
        if ($result.Success) {
            Write-Good "AD-Domain-Services installed successfully"
            if ($result.RestartNeeded -eq 'Yes') { Write-Bad "A restart is required before DC promotion" }
        } else { Write-Bad "Installation reported failure" }
    } catch { Write-Bad "Install-WindowsFeature error: $_" }
    Read-Host "`n`tPress Enter to continue"
}
function Invoke-DomainBreachDCPromoNewForest {
    Write-Host ""
    Write-Host "`t--- DC Promotion: New Forest ---" -ForegroundColor Cyan
    if (-not (Test-ADDSRoleInstalled)) { Write-Bad "AD DS role not installed"; Read-Host; return }
    if (Test-IsDomainController)       { Write-Bad "Already a Domain Controller"; Read-Host; return }

    do { $fqdn = Read-Host "`n`tDomain FQDN (e.g. corp.local)" }
    until ($fqdn -match '^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,}$')

    $netbios = ($fqdn.Split('.')[0]).ToUpper()
    if ($netbios.Length -gt 15) { $netbios = $netbios.Substring(0,15) }
    $nb = Read-Host "`tNetBIOS name [$netbios]"
    if ($nb -ne "") { $netbios = $nb.ToUpper() }

    $dsrm = Read-Host "`tDSRM (Directory Services Restore Mode) password" -AsSecureString

    Write-Host ""
    Write-Host "`t  Domain FQDN  : $fqdn"          -ForegroundColor Yellow
    Write-Host "`t  NetBIOS      : $netbios"        -ForegroundColor Yellow
    Write-Host "`t  Forest/Domain: WinThreshold (Server 2016 max for WS2019)" -ForegroundColor Yellow
    Write-Host "`t  DNS          : Installed automatically"   -ForegroundColor Yellow
    Write-Host "`t  Reboot       : Automatic after promotion" -ForegroundColor Yellow
    Write-Host ""

    $ok = Read-Host "`tProceed? (yes/no)"
    if ($ok.ToLower() -ne 'yes') { Write-Host "`tCancelled." -ForegroundColor Yellow; Read-Host; return }

    Write-Host "`n`t[*] Running prerequisite test..." -ForegroundColor Yellow
    try {
        $test = Test-ADDSForestInstallation -DomainName $fqdn -DomainNetBIOSName $netbios `
            -SafeModeAdministratorPassword $dsrm -ForestMode WinThreshold -DomainMode WinThreshold `
            -InstallDns:$true -Force -ErrorAction Stop
        $errs = $test | Where-Object { $_.Severity -eq 'Error' }
        if ($errs) { $errs | ForEach-Object { Write-Bad $_.Message }; Read-Host; return }
        Write-Good "Prerequisite test passed"
    } catch { Write-Bad "Prerequisite test error: $_"; Read-Host; return }

    Write-Host "`n`t[*] Promoting to Domain Controller..." -ForegroundColor Yellow
    try {
        Install-ADDSForest -DomainName $fqdn -DomainNetBIOSName $netbios `
            -SafeModeAdministratorPassword $dsrm -ForestMode WinThreshold -DomainMode WinThreshold `
            -InstallDns:$true -DatabasePath "C:\Windows\NTDS" -LogPath "C:\Windows\NTDS" `
            -SysvolPath "C:\Windows\SYSVOL" -CreateDnsDelegation:$false -Force -Confirm:$false
    } catch {
        if ($_.Exception.Message -match 'reboot|restart') { Write-Good "Promotion complete � server rebooting" }
        else { Write-Bad "Promotion error: $_"; Read-Host }
    }
}
function Invoke-DomainBreachDCPromoExisting {
    Write-Host ""
    Write-Host "`t--- DC Promotion: Join Existing Domain ---" -ForegroundColor Cyan
    if (-not (Test-ADDSRoleInstalled)) { Write-Bad "AD DS role not installed"; Read-Host; return }
    if (Test-IsDomainController)       { Write-Bad "Already a Domain Controller"; Read-Host; return }

    $fqdn  = Read-DomainName "`n`tExisting domain FQDN"
    $cred  = Get-Credential -Message "Domain Admin credentials for $fqdn"
    $dsrm  = Read-Host "`tDSRM password" -AsSecureString

    Write-Host ""
    Write-Host "`t  Domain : $fqdn"            -ForegroundColor Yellow
    Write-Host "`t  Admin  : $($cred.UserName)" -ForegroundColor Yellow
    Write-Host ""

    $ok = Read-Host "`tProceed? (yes/no)"
    if ($ok.ToLower() -ne 'yes') { Write-Host "`tCancelled." -ForegroundColor Yellow; Read-Host; return }

    try {
        Install-ADDSDomainController -DomainName $fqdn -SafeModeAdministratorPassword $dsrm `
            -Credential $cred -InstallDns:$true -DatabasePath "C:\Windows\NTDS" `
            -LogPath "C:\Windows\NTDS" -SysvolPath "C:\Windows\SYSVOL" -Force -Confirm:$false
    } catch {
        if ($_.Exception.Message -match 'reboot|restart') { Write-Good "Promotion complete � server rebooting" }
        else { Write-Bad "Promotion error: $_"; Read-Host }
    }
}
function Show-DomainBreachDomainInfo {
    Write-Host ""
    try {
        $d  = Get-ADDomain -ErrorAction Stop
        $f  = Get-ADForest -ErrorAction Stop
        $pp = Get-ADDefaultDomainPasswordPolicy -Identity $d.DNSRoot
        Write-Host "`t  Domain       : $($d.DNSRoot)"
        Write-Host "`t  NetBIOS      : $($d.NetBIOSName)"
        Write-Host "`t  Forest       : $($f.Name)"
        Write-Host "`t  Domain Mode  : $($d.DomainMode)"
        Write-Host "`t  Forest Mode  : $($f.ForestMode)"
        Write-Host "`t  PDC Emulator : $($d.PDCEmulator)"
        Write-Host ""
        Write-Host "`t  Password Policy:" -ForegroundColor Yellow
        Write-Host "`t    Complexity  : $($pp.ComplexityEnabled)"
        Write-Host "`t    Min Length  : $($pp.MinPasswordLength)"
        Write-Host "`t    Lockout Dur : $($pp.LockoutDuration)"
        Write-Host ""
        $uc = (Get-ADUser  -Filter * -ErrorAction SilentlyContinue).Count
        $gc = (Get-ADGroup -Filter * -ErrorAction SilentlyContinue).Count
        Write-Host "`t  Users  : $uc"
        Write-Host "`t  Groups : $gc"
    } catch { Write-Bad "Could not retrieve domain info (not a DC?): $_" }
    Read-Host "`n`tPress Enter to continue"
}
function Show-DomainBreachStateFiles {
    Write-Host ""
    $files = Get-ChildItem -Path . -Filter "DomainBreach-State-*.json" -ErrorAction SilentlyContinue
    if ($files) {
        $files | ForEach-Object {
            $kb = [math]::Round($_.Length / 1KB, 1)
            Write-Host "`t  $($_.Name)  [$kb KB]  $($_.LastWriteTime)" -ForegroundColor Cyan
        }
    } else {
        Write-Host "`t  No state files found in current directory." -ForegroundColor Yellow
    }
}
function Invoke-DomainBreachLoadObjects {
    Write-Host "`n`t[*] Loading existing AD users and groups into session..." -ForegroundColor Yellow
    try {
        $Global:CreatedUsers = @(Get-ADUser  -Filter * | Select-Object -ExpandProperty SamAccountName)
        $Global:AllObjects   = @(Get-ADGroup -Filter * | Select-Object -ExpandProperty Name)
        Write-Good "Loaded $($Global:CreatedUsers.Count) users and $($Global:AllObjects.Count) groups"
    } catch { Write-Bad "Failed to load AD objects: $_" }
}
function Show-DomainBreachModuleMenu {
    # SMBv1 prereq check — run once before any modules execute
    if (-not (Invoke-DomainBreachSMBv1PreCheck -Force:$SkipSMBv1Reboot)) { return }
    do {
        Clear-Host
        Write-Host "=================================================" -ForegroundColor Cyan
        Write-Host "        Individual Vulnerability Modules         " -ForegroundColor Cyan
        Write-Host "=================================================" -ForegroundColor Cyan
        if ($Global:Domain -ne "") { Write-Host " Domain : $Global:Domain" -ForegroundColor Green }
        else                       { Write-Host " Domain : not set"         -ForegroundColor Red   }
        if ($Global:CreatedUsers.Count -gt 0) {
            Write-Host " Users loaded : $($Global:CreatedUsers.Count) | Groups : $($Global:AllObjects.Count)" -ForegroundColor Green
        } else {
            Write-Host " No users in session � use [L] to load from AD" -ForegroundColor Yellow
        }
        Write-Host "=================================================" -ForegroundColor Cyan
        Write-Host ""

        Write-Host " KERBEROS ATTACKS" -ForegroundColor Red
        Write-Host "  [1]  KRBTGT Pwd Age           ~50 pts  Simulate 5-yr-old KRBTGT password"
        Write-Host "  [2]  Priv Kerberoast+SchAdm  ~40 pts  DA service acct + Schema Admins"
        Write-Host "  [3]  Unconstrained Deleg      ~30 pts  TrustedForDelegation on accounts"
        Write-Host "  [4]  AS-REP Roasting          ~30 pts  Disable pre-auth on random users"
        Write-Host "  [5]  Kerberoasting            ~25 pts  SPNs with weak passwords"
        Write-Host ""

        Write-Host " DOMAIN COMPROMISE" -ForegroundColor Red
        Write-Host "  [6]  DCSync Rights            ~30 pts  Replication rights to unpriv users"
        Write-Host "  [7]  Bad ACLs                 ~20 pts  GenericAll/WriteDACL on groups"
        Write-Host "  [8]  AdminSDHolder Abuse      ~18 pts  GenericAll on AdminSDHolder object"
        Write-Host "  [9]  DnsAdmins                ~15 pts  Users/groups in DnsAdmins"
        Write-Host ""

        Write-Host " LEGACY PROTOCOLS & SERVICES" -ForegroundColor Yellow
        Write-Host "  [10] Legacy Protocols          ~35 pts  LM Hash, Null Sessions, SMBv1"
        Write-Host "  [11] LDAP Signing + Spooler   ~25 pts  Disable LDAP signing; start Spooler"
        Write-Host "  [12] Disable SMB Signing       ~15 pts  Disable SMB client signing"
        Write-Host ""

        Write-Host " ACCOUNT WEAKNESSES" -ForegroundColor Yellow
        Write-Host "  [13] Guest + Pre-Win2000       ~20 pts  Enable Guest; Authenticated Users"
        Write-Host "  [14] Reversible / DES Crypto   ~18 pts  Reversible encryption + DES Kerberos"
        Write-Host "  [15] SID History               ~12 pts  Fake SID History on users"
        Write-Host "  [16] Password Never Expires    ~12 pts  PasswordNeverExpires on 5-15 users"
        Write-Host "  [17] Pwd in Description         ~8 pts  Plaintext passwords in AD description"
        Write-Host "  [18] Default Password           ~8 pts  Set Changeme123! on random users"
        Write-Host "  [19] Password Spray             ~8 pts  Shared password ncc1701 on users"
        Write-Host ""

        Write-Host "  [L] Load existing AD users and groups into session"
        Show-VerboseLabel
        Write-Host "  [B] Back to main menu"
        Write-Host ""

        if ($Global:Domain -eq "") {
            $Global:Domain = Read-DomainName "`tDomain name"
        }

        $choice = (Read-Host "`tSelect module").ToUpper()
        switch ($choice) {
            '1'  { DomainBreach-KrbtgtPwdAge;                 Write-Good "KRBTGT Pwd Age done";          Read-Host "`tPress Enter" }
            '2'  { DomainBreach-SchemaAdminAndPrivKerberoast;  Write-Good "Schema Admins/PrivKerb done";  Read-Host "`tPress Enter" }
            '3'  { DomainBreach-UnconstrainedDelegation;       Write-Good "Unconstrained Deleg done";     Read-Host "`tPress Enter" }
            '4'  { DomainBreach-ASREPRoasting;                 Write-Good "AS-REP Roasting done";         Read-Host "`tPress Enter" }
            '5'  { DomainBreach-Kerberoasting;                 Write-Good "Kerberoasting done";           Read-Host "`tPress Enter" }
            '6'  { DomainBreach-DCSync;                        Write-Good "DCSync done";                  Read-Host "`tPress Enter" }
            '7'  { DomainBreach-BadAcls;                       Write-Good "Bad ACLs done";                Read-Host "`tPress Enter" }
            '8'  { DomainBreach-AdminSDHolderAbuse;            Write-Good "AdminSDHolder done";           Read-Host "`tPress Enter" }
            '9'  { DomainBreach-DnsAdmins;                     Write-Good "DnsAdmins done";               Read-Host "`tPress Enter" }
            '10' { DomainBreach-LegacyProtocols;               Write-Good "Legacy Protocols done";        Read-Host "`tPress Enter" }
            '11' { DomainBreach-LDAPSigningAndSpooler;         Write-Good "LDAP Sign/Spooler done";       Read-Host "`tPress Enter" }
            '12' { DomainBreach-DisableSMBSigning;             Write-Good "SMB Signing disabled";         Read-Host "`tPress Enter" }
            '13' { DomainBreach-GuestAndPreWin2000;            Write-Good "Guest/Pre-Win2000 done";       Read-Host "`tPress Enter" }
            '14' { DomainBreach-ReversibleAndDESEncryption;    Write-Good "Reversible/DES done";          Read-Host "`tPress Enter" }
            '15' { DomainBreach-SIDHistory;                    Write-Good "SID History done";             Read-Host "`tPress Enter" }
            '16' { DomainBreach-PasswordNeverExpires;          Write-Good "PwdNeverExpires done";         Read-Host "`tPress Enter" }
            '17' { DomainBreach-PwdInObjectDescription;        Write-Good "Pwd in Description done";      Read-Host "`tPress Enter" }
            '18' { DomainBreach-DefaultPassword;               Write-Good "Default Password done";        Read-Host "`tPress Enter" }
            '19' { DomainBreach-PasswordSpraying;              Write-Good "Password Spraying done";       Read-Host "`tPress Enter" }
            'L'  { Invoke-DomainBreachLoadObjects;                                                         Read-Host "`tPress Enter" }
            'V'  { Invoke-DomainBreachVerboseToggle }
            'B'  { return }
            default { Write-Host "`tInvalid option" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($choice -ne 'B')
}
function Show-DomainBreachMenu {
    do {
        Clear-Host
        Write-Host "=================================================" -ForegroundColor Cyan
        Write-Host " DomainBreach - Vulnerable Active Directory Lab  " -ForegroundColor Cyan
        Write-Host "=================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host " SETUP" -ForegroundColor Yellow
        Write-Host "  [1] Check Prerequisites"
        Write-Host "  [2] Install AD DS Role"
        Write-Host "  [3] Promote to Domain Controller  (New Forest)"
        Write-Host "  [4] Promote to Domain Controller  (Join Existing Domain)"
        Write-Host ""
        Write-Host " VULNERABILITIES" -ForegroundColor Yellow
        Write-Host "  [5] Run All Vulnerability Modules"
        Write-Host "  [6] Run Individual Vulnerability Modules"
        Write-Host ""
        Write-Host " MANAGEMENT" -ForegroundColor Yellow
        Write-Host "  [7] Rollback DomainBreach Changes (from state file)"
        Write-Host "  [8] View Domain Information"
        Write-Host "  [9] List Available State Files"
        Write-Host ""
        Show-VerboseLabel
        Write-Host "  [0] Exit"
        Write-Host "=================================================" -ForegroundColor Cyan
        Write-Host ""

        $choice = (Read-Host "`tSelect an option").ToUpper()
        switch ($choice) {
            '1' {
                Invoke-DomainBreachPrerequisiteCheck
            }
            '2' {
                Invoke-DomainBreachRoleInstall
            }
            '3' {
                Invoke-DomainBreachDCPromoNewForest
            }
            '4' {
                Invoke-DomainBreachDCPromoExisting
            }
            '5' {
                if (-not (Invoke-DomainBreachSMBv1PreCheck -Force:$SkipSMBv1Reboot)) { Read-Host "`n`tPress Enter"; continue }
                $d   = Read-DomainName "`n`tDomain name"
                $ls  = Read-Host "`tUsers to create [100]"
                $l   = if ($ls -eq "") { 100 } else { [int]$ls }
                $sf  = Read-Host "`tState file path (blank = auto)"
                $oui = Read-Host "`tTarget OU name [DomainBreach]"
                $ou  = if ($oui -eq "") { "DomainBreach" } else { $oui }
                Invoke-DomainBreach -DomainName $d -UsersLimit $l -StateFile $sf -TargetOU $ou
                Read-Host "`n`tPress Enter to continue"
            }
            '6' {
                Show-DomainBreachModuleMenu
            }
            '7' {
                Show-DomainBreachStateFiles
                $sf = Read-Host "`n`tEnter path to state file"
                if ($sf -ne "" -and (Test-Path $sf)) {
                    Invoke-DomainBreach-Rollback -StateFile $sf
                } else {
                    Write-Bad "State file not found or no path provided"
                }
                Read-Host "`n`tPress Enter to continue"
            }
            '8' {
                Show-DomainBreachDomainInfo
            }
            '9' {
                Show-DomainBreachStateFiles
                Read-Host "`n`tPress Enter to continue"
            }
            'V' { Invoke-DomainBreachVerboseToggle }
            '0' { return }
            default { Write-Host "`tInvalid option" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($choice -ne '0')
}
function Invoke-DomainBreach {
<#
.SYNOPSIS
    Populates an AD domain with randomised users, groups, and 19 intentional misconfigurations.

.DESCRIPTION
    Invoke-DomainBreach is the core population function called by both the -Populate CLI switch
    and menu option [5]. It creates randomised users and groups, then runs all 19 vulnerability
    modules in sequence:

      Kerberos     : KRBTGT pwd age, privileged Kerberoast, unconstrained delegation,
                     AS-REP roasting, Kerberoasting (SPNs with weak passwords)
      Compromise   : DCSync rights, bad ACLs, AdminSDHolder abuse, DnsAdmins membership
      Legacy       : LM hash, null sessions, SMBv1, LDAP signing disabled, Print Spooler,
                     SMB client signing disabled
      Accounts     : Guest enabled, Pre-Win2000, reversible encryption, DES Kerberos,
                     password never expires, password in description, default/shared passwords,
                     SID History injection

    All changes are tracked in $Global:DomainBreachState and written to a JSON state file so
    the environment can be cleanly reversed with Invoke-DomainBreach-Rollback.

    Set $Global:VerboseMode = $true (or pass -VerboseMode to the script) before calling this
    function to see per-operation [*] progress lines and yellow [DBG] error messages for any
    steps that fail silently under normal operation.

.PARAMETER DomainName
    Fully-qualified DNS name of the target domain (e.g. corp.local). Mandatory.

.PARAMETER UsersLimit
    Number of randomised AD user accounts to create. Defaults to 100.

.PARAMETER StateFile
    Path where the JSON state file will be written after the run. If blank, a filename is
    generated automatically as DomainBreach-State-<domain>-<timestamp>.json in the current directory.

.PARAMETER TargetOU
    Name of the Organizational Unit under the domain root where all created objects will be placed.
    Defaults to "DomainBreach". The OU is created if it does not exist and its DN is recorded in
    the state file. Pass an empty string to use default AD containers instead.
    Rollback removes the OU automatically when OUCreated is true in the state file.

.EXAMPLE
    Invoke-DomainBreach -DomainName corp.local

    Run with default settings (100 users). Objects go into OU=DomainBreach,DC=corp,DC=local.

.EXAMPLE
    Invoke-DomainBreach -DomainName corp.local -TargetOU "RedTeamLab"

    Place all created objects under OU=RedTeamLab,DC=corp,DC=local.

.EXAMPLE
    $Global:VerboseMode = $true
    Invoke-DomainBreach -DomainName corp.local -UsersLimit 50

    Enable verbose/debug mode first, then run with 50 users. Every [*] step and any [DBG]
    error lines will be printed to the console for easy troubleshooting.

.EXAMPLE
    .\domainbreach.ps1 -Populate -DomainName corp.local -VerboseMode

    Equivalent to the above but using the script-level -VerboseMode switch directly.

.EXAMPLE
    Get-Help Invoke-DomainBreach -Full

    Show this full help page.

.NOTES
    Author  : Tyler Reese (@tyler_reese)
    Purpose : Lab / CTF environment setup - DO NOT run on production domains.
#>
    [CmdletBinding()]
    Param(
        [int]$UsersLimit = 100,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainName,
        [string]$StateFile = "",
        [string]$TargetOU  = "DomainBreach"
    )
    $Global:Domain = $DomainName

    if ($StateFile -eq "") {
        $StateFile = ".\DomainBreach-State-$DomainName-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    }
    $Global:DomainBreachState.Domain    = $Global:Domain
    $Global:DomainBreachState.Timestamp = (Get-Date -Format 'o')

    # Create (or verify) the target OU before any objects are laid down
    if ($TargetOU -ne "") {
        $domainDN = (Get-ADDomain -Identity $DomainName -ErrorAction SilentlyContinue).DistinguishedName
        if ($domainDN) {
            $Global:TargetOU = Ensure-DomainBreachOU -OUName $TargetOU -DomainDN $domainDN
        } else {
            Write-Bad "Could not resolve domain DN for '$DomainName' — objects will be created in default containers"
            $Global:TargetOU = ""
        }
    } else {
        $Global:TargetOU = ""
        Write-Info "No TargetOU specified — objects will be created in default AD containers"
    }

    $origPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $Global:Domain
    $Global:DomainBreachState.PasswordPolicy = @{
        LockoutDuration             = $origPolicy.LockoutDuration.ToString()
        LockoutObservationWindow    = $origPolicy.LockoutObservationWindow.ToString()
        ComplexityEnabled           = [bool]$origPolicy.ComplexityEnabled
        ReversibleEncryptionEnabled = [bool]$origPolicy.ReversibleEncryptionEnabled
        MinPasswordLength           = [int]$origPolicy.MinPasswordLength
    }
    $origSmb = Get-SmbClientConfiguration
    $Global:DomainBreachState.SMBSigningEnabled  = [bool]$origSmb.EnableSecuritySignature
    $Global:DomainBreachState.SMBSigningRequired = [bool]$origSmb.RequireSecuritySignature

    $step  = 0
    $total = 23
    $act   = "DomainBreach [$DomainName]"

    Write-Progress -Activity $act -Status "Configuring password policy..." -PercentComplete ([math]::Round((++$step/$total)*100))
    Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain -LockoutDuration 00:01:00 -LockoutObservationWindow 00:01:00 -ComplexityEnabled $false -ReversibleEncryptionEnabled $False -MinPasswordLength 4

    Write-Progress -Activity $act -Status "Creating $UsersLimit users..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-AddADUser -limit $UsersLimit
    $Global:DomainBreachState.Users = $Global:CreatedUsers
    Write-Good "Users Created ($($Global:CreatedUsers.Count))"

    Write-Progress -Activity $act -Status "Creating groups..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-AddADGroup -GroupList $Global:HighGroups
    DomainBreach-AddADGroup -GroupList $Global:MidGroups
    DomainBreach-AddADGroup -GroupList $Global:NormalGroups
    $Global:DomainBreachState.Groups = $Global:AllObjects
    Write-Good "Groups Created"

    Write-Progress -Activity $act -Status "Configuring Bad ACLs..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-BadAcls
    Write-Good "BadACL Done"

    Write-Progress -Activity $act -Status "Configuring Kerberoasting..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-Kerberoasting
    Write-Good "Kerberoasting Done"

    Write-Progress -Activity $act -Status "Configuring AS-REP Roasting..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-ASREPRoasting
    Write-Good "AS-REPRoasting Done"

    Write-Progress -Activity $act -Status "Configuring DnsAdmins..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-DnsAdmins
    Write-Good "DnsAdmins Done"

    Write-Progress -Activity $act -Status "Storing passwords in descriptions..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-PwdInObjectDescription
    Write-Good "Password In Object Description Done"

    Write-Progress -Activity $act -Status "Setting default passwords..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-DefaultPassword
    Write-Good "Default Password Done"

    Write-Progress -Activity $act -Status "Configuring password spraying targets..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-PasswordSpraying
    Write-Good "Password Spraying Done"

    Write-Progress -Activity $act -Status "Granting DCSync rights..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-DCSync
    Write-Good "DCSync Done"

    Write-Progress -Activity $act -Status "Disabling SMB signing..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-DisableSMBSigning
    Write-Good "SMB Signing Disabled"

    Write-Progress -Activity $act -Status "Simulating stale KRBTGT password..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-KrbtgtPwdAge
    Write-Good "KRBTGT Password Age Simulated"

    Write-Progress -Activity $act -Status "Enabling unconstrained delegation..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-UnconstrainedDelegation
    Write-Good "Unconstrained Delegation Done"

    Write-Progress -Activity $act -Status "Schema Admins / privileged Kerberoasting..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-SchemaAdminAndPrivKerberoast
    Write-Good "Schema Admins / Privileged Kerberoast Done"

    Write-Progress -Activity $act -Status "Enabling Guest and Pre-Windows 2000 access..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-GuestAndPreWin2000
    Write-Good "Guest and Pre-Windows 2000 Done"

    Write-Progress -Activity $act -Status "Enabling reversible and DES encryption..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-ReversibleAndDESEncryption
    Write-Good "Reversible/DES Encryption Done"

    Write-Progress -Activity $act -Status "Setting PasswordNeverExpires on accounts..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-PasswordNeverExpires
    Write-Good "PasswordNeverExpires Done"

    Write-Progress -Activity $act -Status "Enabling legacy protocols (LM Hash, Null Sessions, SMBv1)..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-LegacyProtocols
    Write-Good "Legacy Protocols Done"

    Write-Progress -Activity $act -Status "Disabling LDAP signing / starting Print Spooler..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-LDAPSigningAndSpooler
    Write-Good "LDAP Signing / Spooler Done"

    Write-Progress -Activity $act -Status "Modifying AdminSDHolder ACL..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-AdminSDHolderAbuse
    Write-Good "AdminSDHolder Done"

    Write-Progress -Activity $act -Status "Adding SID History to accounts..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-SIDHistory
    Write-Good "SID History Done"

    Write-Progress -Activity $act -Status "Saving state file..." -PercentComplete ([math]::Round((++$step/$total)*100))
    DomainBreach-SaveState -Path $StateFile
    Write-Progress -Activity $act -Completed
}

if ($Rollback) {
    if ($StateFile -eq "") { Write-Bad "Specify -StateFile <path> when using -Rollback"; exit 1 }
    Invoke-DomainBreach-Rollback -StateFile $StateFile
} elseif ($Check) {
    Invoke-DomainBreachPrerequisiteCheck
} elseif ($Setup) {
    Invoke-DomainBreachRoleInstall
    Invoke-DomainBreachDCPromoNewForest
} elseif ($Populate) {
    if ($DomainName -eq "") {
        $DomainName = Get-AutoDiscoveredDomain
        if ($DomainName -eq "") { Write-Bad "Specify -DomainName when using -Populate (auto-discovery failed)"; exit 1 }
        Write-Good "Auto-discovered domain: $DomainName"
    }
    if (-not (Invoke-DomainBreachSMBv1PreCheck -Force:$SkipSMBv1Reboot)) { exit 0 }
    Invoke-DomainBreach -DomainName $DomainName -UsersLimit $UsersLimit -StateFile $StateFile -TargetOU $TargetOU
} elseif ($Menu -or $DomainName -eq "") {
    Show-DomainBreachMenu
} else {
    # Direct CLI: domain name supplied without an explicit mode switch
    if (-not (Invoke-DomainBreachSMBv1PreCheck -Force:$SkipSMBv1Reboot)) { exit 0 }
    Invoke-DomainBreach -DomainName $DomainName -UsersLimit $UsersLimit -StateFile $StateFile -TargetOU $TargetOU
}
