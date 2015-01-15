

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

    Process
    {
        $group = Get-SecurityObject -Identity $Identity
        $groupBase= $group.PSBase
        
        $Members | % {
            
            $member = Get-SecurityObject -Identity $_
            $memberBase= $member.PSBase


            Write-Debug ('{0}: Group: {1}, Member: {2}' -f $MyInvocation.MyCommand, $group.PSBase.Path, $member.PSBase.Path)

            If ($PSCmdlet.ShouldProcess(('Member "{0}" of group "{1}"' -f $memberBase.Path, $groupBase.Path)))
            {
                # Make sure that $group is actually a group.
                If ($group.groupType -eq "")
                {
                    Throw ('The Security object "{0}" is not a group and cannot have members added to it.' -f $groupBase.Path)
                }

                # Wrap the action and status message in a try/catch so that it
                # doesn't give spurious status outputs.
                Try 
                {
                    $group.PSBase.Invoke("Add",$member.PSBase.Path)

                    Write-Verbose ('The member {0} was successfully added to the group {1}.' -f $member.PSBase.Path, $group.PSBase.Path)
                }
                # I'm not sure how to handle this, yet, so just rethrow the
                # full exception.
                Catch
                {
                    Throw $_
                }
            }
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

    Process
    {
        $group = Get-SecurityObject -Identity $Identity
        $groupBase = $group.PSBase
        
        $Members | % {
            
            $member = Get-SecurityObject -Identity $_
            $memberBase = $member.PSBase

            If ($PSCmdlet.ShouldProcess(('Member "{0}" of group "{1}"' -f $memberBase.Path, $groupBase.Path)))
            {
                # Wrap the action and status message in a try/catch so that it
                # doesn't give spurious status outputs.
                Try
                {
                    $group.PSBase.Invoke("Remove",$member.PSBase.Path)

                    Write-Verbose ('The member {0} was successfully removed from the group {1}' -f $memberBase.Path, $groupBase.Path)
                }
                # I'm not sure how to handle this, yet, so just rethrow the
                # full exception.
                Catch
                {
                    Throw $_
                }
            }
        }
    }
}





<#
$groupName = "Administrators"
$membersToRemove = "Administrator"

$servers | % {
    Get-SecurityObject -Domain $_ -Identity $groupName |
    Remove-GroupMember -Members $membersToRemove -WhatIf
}
#>
