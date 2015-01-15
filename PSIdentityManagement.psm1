

function Get-SecurityObject {
    <#
    
    #>
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [string]
        $Identity
    )

    Process
    {
        # Assume the local domain unless specified.
        $domain = "."

        # If a Domain is specified, split on the backslash.
        If ($Identity -like '*\*')
        {
            Write-Debug `
                ('{0}: $Identity contained a backslash: {1}' -f $MyInvocation.MyCommand, $Identity)

            $identityParts = $Identity.Split("\")
            $domain = $identityParts[0]
            $securityObjectIdentifier = $identityParts[1]
        }
        # Otherwise, consider the Identity string as the object to retrieve
        else
        {
            Write-Debug `
                ('$Identity did not contain a backslash: {0}' -f $Identity)

            $securityObjectIdentifier = $Identity
        }

        $queryString = "WinNT://$domain/$securityObjectIdentifier"

        Write-Debug `
            ('{0}: ADSI query: {1}' -f $MyInvocation.MyCommand, $queryString)

        $securityObject = [ADSI]($queryString)

        # Verify that the ADSI searcher actually found it. The object
        # should contain a Name property.
        If ( !($securityObject.Name) )
        {
            Throw ('The security object "{0}" could not be found.' -f $Identity)
        }

        $securityObject
    }
}





function Add-GroupMember {
    <##>

    [CmdletBinding(
        SupportsShouldProcess=$True,
        ConfirmImpact="Medium"
    )]
    param
    (
        # Accept groups in pipeline input
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [string]
        $Identity,

        [parameter(Mandatory=$True)]
        [string]
        $Members
    )

    Begin
    {
        [string]$TargetFormat = 'Member "{0}" of group "{1}"'
    }

    Process
    {
        If ($PSCmdlet.ShouldProcess(($TargetFormat -f $Members, $Identity)))
        {
            Set-GroupMembership -Identity $Identity -Members $Members -Disposition 'Add'
        }
    }
}






function Remove-GroupMember {
    <##>

    [CmdletBinding(
        SupportsShouldProcess=$True,
        ConfirmImpact="High"
    )]
    param
    (
        # Accept groups in pipeline input
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [string]
        $Identity,

        [parameter(Mandatory=$True)]
        [string]
        $Members
    )

    Begin
    {
        [string]$TargetFormat = 'Member "{0}" of group "{1}"'
    }

    Process
    {
        If ($PSCmdlet.ShouldProcess(($TargetFormat -f $Members, $Identity)))
        {
            Set-GroupMembership -Identity $Identity -Members $Members -Disposition 'Remove'
        }
    }
}






function Set-GroupMembership {
    <##>

    [CmdletBinding(SupportsShouldProcess=$False)]
    param
    (
        # Accept groups in pipeline input
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [string]
        $Identity,

        [parameter(Mandatory=$True)]
        [string]
        $Members,

        [parameter(Mandatory=$True)]
        [ValidateSet("Add","Remove")]
        [string]$Disposition
    )

    Begin
    {
        IF ( $Disposition -eq "Add" )
        {
            [string]$NotAGroupExceptionFormat = 'The Security object "{0}" is not a group and cannot have members added to it.'
            [string]$ResultFormat = 'The member {0} was successfully added to group {1}'
        }
        Else
        {
            [string]$NotAGroupExceptionFormat = 'The Security object "{0}" is not a group and cannot have members removed from it.'
            [string]$ResultFormat = 'The member {0} was successfully removed from the group {1}'
        }
    }

    Process
    {
        $group = Get-SecurityObject -Identity $Identity
        $groupBase = $group.PSBase
        
        $Members | % {
            
        Try
        {
            $member = Get-SecurityObject -Identity $_
            $memberBase = $member.PSBase
        }
        Catch
        {
            Throw $_
        }

            # Make sure that $group is actually a group.
            If ($group.groupType -eq "")
            {
                Throw ($NotAGroupExceptionFormat -f $groupBase.Path)
            }

            # Wrap the action and status message in a try/catch so that it
            # doesn't give spurious status outputs, or stop processing 
            # unnecessarily.
            Try
            {
                $group.PSBase.Invoke($Disposition,$member.PSBase.Path)

                # Write the result to the verbose stream.
                Write-Verbose ($ResultFormat -f $memberBase.Path, $groupBase.Path)
            }
            Catch [System.Management.Automation.MethodInvocationException]
            {
                If ($_.Exception.InnerException.ErrorCode -eq '-2147023519')
                {
                    # The specified account is not a member of the group
                    # that we attempted to remove it from.
                    Write-Warning $_.Exception.InnerException.Message
                }
                ElseIf ($_.Exception.InnerException.ErrorCode -eq '-2147023518')
                {
                    # The specified account is already a member of the group
                    # that we attempted to add it to.
                    Write-Warning $_.Exception.InnerException.Message
                }
                Else
                {
                    Throw $_
                }
            }
            Catch
            {
                Write-Verbose 'An Unknown Exception Occurred'
                Throw $_
            }
        }
    }
}

