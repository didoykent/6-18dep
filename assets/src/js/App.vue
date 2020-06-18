<template >
  <v-app>

  <div v-if = "$route.name === 'admin'">

    <v-navigation-drawer expand-on-hover permanent fixed floating width="300" mole-break-point="991" app dark persistent>
      <v-img src="" height="100%">
        <v-list-item link @click="userSettings = !userSettings">
          <v-list-item-avatar>
            <v-img src="https://image.flaticon.com/icons/svg/265/265674.svg" height="40" min-height="40" width="40" />
          </v-list-item-avatar>
          <v-list-item-content>
            <v-list-item-title>
              LMS v0.1
            </v-list-item-title>
          </v-list-item-content>
          <v-list-item-icon>
            <v-icon>mdi-menu-down</v-icon>
          </v-list-item-icon>
        </v-list-item>
        <v-list v-if="userSettings" dense nav>
          <v-list-item-group>
            <v-list-item links>
              <v-list-item-icon text>
                PF
              </v-list-item-icon>
              <v-list-item-content>
                <v-list-item-title>
                  Profile
                </v-list-item-title>
              </v-list-item-content>
            </v-list-item>
            <v-list-item links>
              <v-list-item-icon text>
                BI
              </v-list-item-icon>
              <v-list-item-content>
                <v-list-item-title>
                  Bio
                </v-list-item-title>
              </v-list-item-content>
            </v-list-item>
          </v-list-item-group>
        </v-list>



        <v-divider></v-divider>

        <v-list nav dense>
          <v-list-item @click="setMenu('dashboard')" links style="background-color: #e91e63 !important;
          border-color: #e91e63 !important;">
          <v-list-item-icon>
            <v-icon>mdi-folder</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Dashboard</v-list-item-title>
        </v-list-item>





        <v-list-item link @click="setMenu('members'), $router.push('/Member')">
          <v-list-item-icon>
            <v-icon>mdi-account-multiple</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Members</v-list-item-title>
        </v-list-item>





        <v-list-item link @click="setMenu('classes'), $router.push('/MemberClass')">
          <v-list-item-icon>
            <v-icon>mdi-book-variant</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Classes</v-list-item-title>
        </v-list-item>




        <v-list-item link @click="setMenu('boards'), $router.push('/MemberBoards')">
          <v-list-item-icon>
            <v-icon>mdi-clipboard-text</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Boards</v-list-item-title>
        </v-list-item>



      </v-list>
    </v-img>
  </v-navigation-drawer>

  </div>
  <div v-if = "$route.name === 'student'">

    <v-navigation-drawer expand-on-hover permanent fixed floating width="300" mole-break-point="991" app dark persistent>
      <v-img src="" height="100%">
        <v-list-item link @click="userSettings = !userSettings">
          <v-list-item-avatar>
            <v-img src="https://image.flaticon.com/icons/svg/265/265674.svg" height="40" min-height="40" width="40" />
          </v-list-item-avatar>
          <v-list-item-content>
            <v-list-item-title>
              LMS v0.1
            </v-list-item-title>
          </v-list-item-content>
          <v-list-item-icon>
            <v-icon>mdi-menu-down</v-icon>
          </v-list-item-icon>
        </v-list-item>
        <v-list v-if="userSettings" dense nav>
          <v-list-item-group>
            <v-list-item links>
              <v-list-item-icon text>
                PF
              </v-list-item-icon>
              <v-list-item-content>
                <v-list-item-title>
                  Profile
                </v-list-item-title>
              </v-list-item-content>
            </v-list-item>
            <v-list-item links>
              <v-list-item-icon text>
                BI
              </v-list-item-icon>
              <v-list-item-content>
                <v-list-item-title>
                  Bio
                </v-list-item-title>
              </v-list-item-content>
            </v-list-item>
          </v-list-item-group>
        </v-list>


        <v-divider></v-divider>

        <v-list nav dense>
          <v-list-item links style="background-color: #0088cc !important;
          border-color: #0088cc !important;" @click="$router.push('/StudentDashboard')">
          <v-list-item-icon>
            <v-icon>mdi-folder</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Dashboard</v-list-item-title>
        </v-list-item>

        <v-list-item link  @click="$router.push('/StudentWritingCorrection')">
          <v-list-item-icon>
            <v-icon>mdi-clipboard-text</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Writing Correction</v-list-item-title>
        </v-list-item>

        <v-list-item link @click="$router.push('/StudentQA')">
          <v-list-item-icon>
            <v-icon>question_answer</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Q&A</v-list-item-title>
        </v-list-item>

        <v-list-item link>
          <v-list-item-icon>
            <v-icon>event_note</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Events</v-list-item-title>
        </v-list-item>

        <v-list-item link @click="$router.push('/StudentFAQ')">
          <v-list-item-icon>
            <v-icon>mdi-help</v-icon>
          </v-list-item-icon>
          <v-list-item-title>FAQs</v-list-item-title>
        </v-list-item>

        <v-list-item link>
          <v-list-item-icon>
            <v-icon>mdi-settings</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Account Setting</v-list-item-title>
        </v-list-item>

      </v-list>
    </v-img>
  </v-navigation-drawer>

  </div>

  <div v-if = "$route.name === 'team_leader'">

    <v-navigation-drawer expand-on-hover permanent fixed floating width="300" mole-break-point="991" app dark persistent>
      <v-img src="" height="100%">
        <v-list-item link @click="userSettings = !userSettings">
          <v-list-item-avatar>
            <v-img src="https://image.flaticon.com/icons/svg/265/265674.svg" height="40" min-height="40" width="40" />
          </v-list-item-avatar>
          <v-list-item-content>
            <v-list-item-title>
              LMS v0.1
            </v-list-item-title>
          </v-list-item-content>
          <v-list-item-icon>
            <v-icon>mdi-menu-down</v-icon>
          </v-list-item-icon>
        </v-list-item>
        <v-list v-if="userSettings" dense nav>
          <v-list-item-group>
            <v-list-item links>
              <v-list-item-icon text>
                PF
              </v-list-item-icon>
              <v-list-item-content>
                <v-list-item-title>
                  Profile
                </v-list-item-title>
              </v-list-item-content>
            </v-list-item>
            <v-list-item links>
              <v-list-item-icon text>
                BI
              </v-list-item-icon>
              <v-list-item-content>
                <v-list-item-title>
                  Bio
                </v-list-item-title>
              </v-list-item-content>
            </v-list-item>
          </v-list-item-group>
        </v-list>


        <v-divider></v-divider>

        <v-list nav dense>
          <v-list-item links style="background-color: #e91e63 !important;
          border-color: #e91e63 !important;" >
          <v-list-item-icon>
            <v-icon>mdi-folder</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Dashboard</v-list-item-title>
        </v-list-item>

        <v-list-item link @click="this.$router.push('/TeamMember')">
          <v-list-item-icon>
            <v-icon>mdi-account-multiple</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Members</v-list-item-title>
        </v-list-item>

        <v-list-item link>
          <v-list-item-icon>
            <v-icon>mdi-book-variant</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Classses</v-list-item-title>
        </v-list-item>

        <v-list-item link>
          <v-list-item-icon>
            <v-icon>mdi-clipboard-text</v-icon>
          </v-list-item-icon>
          <v-list-item-title>Boards</v-list-item-title>
        </v-list-item>

      </v-list>
    </v-img>
  </v-navigation-drawer>

  </div>





  <v-content>
    <router-view>
    </router-view>
  </v-content>
</v-app>
</template>

<script>
import axios from 'axios'
export default {
  data(){
    return{
      userSettings: false,
      expand: false,
      menus: {
        dashboard: false,
        members: false,
        classes: false,
        boards: false
      },


    }
  },

  mounted(){




    console.log(this.$route)
  },

  watch: {
    $route(to, from) {
      console.log(to)
      console.log(from)
    }

  },

  methods: {
    setMenu(selectedMenu){
      for(var menu in this.menus){
        if(menu === selectedMenu){
          this.menus[menu] = !this.menus[menu]
        }
        else{
          this.menus[menu] = false
        }
      }
      console.log(this.menus)
    },

    async  getUser(){

    await this.$store.dispatch('checkAuth')





    }


  }
}
</script>

<style>
/* Remove in 1.2 */
.v-datatable thead th.column.sortable i {
  vertical-align: unset;
}
</style>
