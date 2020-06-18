<template>
  <v-app>
    <v-container>
      <v-row>
        <v-col :cols="leftColumn">
          <v-card flat style="width:100%;height:100%">
            <v-container>
              <v-row>
                <iframe class="iframe-placeholder" src="http://178.128.213.14/" style="height:1012px;width:92%"></iframe>
                <v-spacer></v-spacer>
                <v-icon large color="primary" @click="showMenu">{{arrow}}</v-icon>
              </v-row>
            </v-container>
          </v-card>
        </v-col>
        <v-col :cols="rightColumn">
          <v-card style="width:100%;height:100%" :style="rightStyle" class="px-2">
            <v-container>


              <v-alert
   prominent
   type="error"
   v-if = "EvaluationError"
 >
   <v-row align="center">
     <v-col class="grow">All Fields are required.</v-col>

   </v-row>
 </v-alert>

              <v-row>

                <v-card class="ml-3" color="#428bca" flat tile>
                  <v-card-text>Today | {{date}} | {{time}}</v-card-text>
                </v-card>


              </v-row>


              <v-row>
                <v-container>
                  <v-simple-table>
                    <template v-slot:default>
                      <thead>
                        <tr style="background-color:#6bbde9">
                          <th class="text-left">Class ID</th>
                          <th>Class Type</th>
                          <th>EOC</th>
                          <th>Days</th>
                          <th>Schedule</th>
                          <th>Duration</th>
                          <th>Teacher</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        <td class="text-left">{{Class['schedule']['classid']}}</td>
                        <td>{{Class['schedule']['class_type']}}</td>
                        <td>{{getEndContract()}}</td>
                        <td>{{getApplicableDays()}}</td>
                        <td>{{getHour()}}</td>
                        <td>{{Class['schedule']['duration']}}</td>
                        <td>{{Tutor['mega_name']}}</td>
                        <td></td>
                      </tbody>
                    </template>
                  </v-simple-table>
                  <v-divider></v-divider>
                </v-container>
              </v-row>
              <v-row>
                <v-col sm="12" md="7">
                  <v-row>
                    <v-col class="py-0 pr-0 font-italic" cols="3">Student</v-col>
                    <v-col class="py-0 pr-0">{{Class['schedule']['name']}}</v-col>
                  </v-row>
                  <v-divider class="my-2"></v-divider>
                  <v-row>
                    <v-col class="py-0 pr-0 font-italic" align-self="center" cols="3"> Attendance</v-col>
                    <v-col class="py-0 pr-0" cols="5">
                      <v-select class="pt-0"  v-model = "Attendance" :items="attendance" regular></v-select>
                    </v-col>
                  </v-row>
                  <v-divider class="my-2"></v-divider>
                  <v-row>
                    <v-col class="py-0 pr-0 font-italic" align-self="center" cols="3">Level</v-col>
                    <v-col class="py-0 pr-0" align-self="center" cols="5" v-if="isSetLevel">{{Level}}</v-col>
                    <v-col class="py-0 pr-0" cols="5" v-if="!isSetLevel">
                      <v-select class="pt-0" :items="levels" v-model = "Level" regular></v-select>
                    </v-col>
                    <v-col class="py-0 pr-0">

                      <v-btn color="primary" small @click="UpdateLevel" v-if = "isSetLevel">Update</v-btn>
                      <v-btn color="primary" small @click="SaveLevel" v-if = "!isSetLevel">Save</v-btn>
                    </v-col>
                  </v-row>
                  <v-divider></v-divider>
                  <v-row>
                    <v-col class="py-0 pr-0 font-italic" align-self="center" cols="3">Curriculum</v-col>
                    <v-col class="py-0 pr-0" cols="5" v-if="isSetCurriculum">{{Curriculum}}</v-col>
                    <v-col class="py-0 pr-0" cols="5" v-if="!isSetCurriculum">
                      <v-select @change="onChangeCurriculum($event)"  v-model = "Curriculum" class="pt-0" :items="curriculums" regular></v-select>
                    </v-col>
                    <v-col class="py-0 pr-0">
                      <v-btn color="primary" small @click="UpdateCurriculum" v-if = "isSetCurriculum">Update</v-btn>
                      <v-btn color="primary" small @click="SaveCurriculum" v-if = "!isSetCurriculum">Save</v-btn>
                    </v-col>
                  </v-row>
                  <v-row>
                    <v-col class="py-0 pr-0 font-italic" align-self="center" cols="3">Material</v-col>
                    <v-col class="py-0 pr-0" align-self="center" v-if="isSetCurriculum">{{Material}}</v-col>
                    <v-col class="py-0 pr-0" cols="5" v-if="!isSetCurriculum ">
                      <v-select class="pt-0" v-model = "Material" :items="books" regular></v-select>
                    </v-col>
                  </v-row>
                </v-col>

                <v-col sm="12" md="5">

                  <v-row>
                    <v-col class="font-weight-bold py-0 pr-0" cols="6">Skill</v-col>
                    <v-col class="font-weight-bold py-0 pr-0" cols="4">Score</v-col>
                  </v-row>
                  <v-divider class="my-2"></v-divider>
                  <v-row>
                    <v-col cols="6" class="py-0 pr-0" align-self="center">Pronunciation</v-col>
                    <v-col cols="4" class="py-0 pr-0">
                      <v-select class="pt-0" v-model = "Pronunciation" :items="scores" regular></v-select>
                    </v-col>
                  </v-row>
                  <v-divider class="my-2"></v-divider>
                  <v-row>
                    <v-col cols="6" class="py-0 pr-0" align-self="center">Grammar</v-col>
                    <v-col cols="4" class="py-0 pr-0">
                      <v-select class="pt-0" v-model = "Grammar" :items="scores" regular></v-select>
                    </v-col>
                  </v-row>
                  <v-divider class="my-2"></v-divider>
                  <v-row>
                    <v-col cols="6" class="py-0 pr-0"  align-self="center">Comprehension</v-col>
                    <v-col cols="4" class="py-0 pr-0">
                      <v-select class="pt-0"  v-model = "Comprehension" :items="scores" regular></v-select>
                    </v-col>
                  </v-row>
                  <v-divider class="my-2"></v-divider>
                  <v-row>
                    <v-col cols="6" class="py-0 pr-0"  align-self="center">Fluency</v-col>
                    <v-col cols="4" class="py-0 pr-0">
                      <v-select class="pt-0"  v-model = "Fluency" :items="scores" regular></v-select>
                    </v-col>
                  </v-row>
                </v-col>
              </v-row>

              <v-divider></v-divider>

              <v-row>
                <v-card tile color="#bbdefb" width="100%" flat>
                  <v-card-text class="text-center black--text">Evaluation</v-card-text>
                </v-card>
              </v-row>

              <v-row>
                <v-col class="py-0 pr-0" align-self="center" cols="3">Lesson/Topic</v-col>
                <v-col class="py-0 pr-0" cols="8">
                  <v-text-field v-model = "Lesson"regular placeholder="Lesson/Topic"></v-text-field>
                </v-col>
              </v-row>

              <v-divider class="my-0"></v-divider>

              <v-row>
                <v-col class="py-0 pr-0" align-self="center" cols="3">Page Number</v-col>
                <v-col class="py-0 pr-0" cols="3">
                  <v-text-field v-model = "pageNumber"regular placeholder="Page Number"></v-text-field>
                </v-col>
              </v-row>

              <v-divider></v-divider>

              <v-row class="mb-2">
                <v-card tile color="#d0f4f9" width="100%" flat>
                  <v-card-text class="text-center black--text">Sentences</v-card-text>
                </v-card>
              </v-row>

              <v-row>
                <v-col class="py-0 pr-0 font-italic" align-self="center" cols="6">Constructed</v-col>
                <v-col class="py-0 pr-0 font-italic" align-self="center" cols="6">Corrected</v-col>
              </v-row>
              <v-divider class="my-0"></v-divider>
              <v-row>
                <v-col class="py-0 pr-0" cols="6">
                  <v-text-field regular v-model = "Constructed1" placeholder="Constructed Sentence 1"></v-text-field>
                </v-col>
                <v-col class="py-0 pr-0" cols="6">
                  <v-text-field regular v-model = "Corrected1" placeholder="Corrected Sentence 1"></v-text-field>
                </v-col>
              </v-row>
              <v-divider class="my-0"></v-divider>
              <v-row>
                <v-col class="py-0 pr-0" cols="6">
                  <v-text-field regular v-model = "Constructed2" placeholder="Constructed Sentence 2"></v-text-field>
                </v-col>
                <v-col class="py-0 pr-0" cols="6">
                  <v-text-field regular v-model = "Corrected2" placeholder="Corrected Sentence 2"></v-text-field>
                </v-col>
              </v-row>

              <v-divider></v-divider>

              <v-row class="mb-2">
                <v-card tile color="#d0f4f9" width="100%" flat>
                  <v-card-text class="text-center black--text">Encountered Words</v-card-text>
                </v-card>
              </v-row>

              <v-row>
                <v-col class="py-0 pr-0 font-italic" align-self="center" cols="6">Word</v-col>
                <v-col class="py-0 pr-0 font-italic" align-self="center" cols="6">Transcript</v-col>
              </v-row>
              <v-divider class="my-0"></v-divider>
              <v-row>
                <v-col class="py-0 pr-0" cols="6">
                  <v-text-field regular placeholder="Word 1" v-model="wordTranscript1" :loading="loadingTranscript1" append-icon="search" @click:append="getTranscript1()"></v-text-field>
                </v-col>
                <v-col align-self="center" jsu class="py-0 pr-0" cols="6">
                  <v-row justify="center">{{transcript1}}</v-row>
                </v-col>
              </v-row>
              <v-divider class="my-0"></v-divider>
              <v-row>
                <v-col class="py-0 pr-0" cols="6">
                  <v-text-field regular placeholder="Word 2" v-model="wordTranscript2" :loading="loadingTranscript2" append-icon="search" @click:append="getTranscript2()"></v-text-field>
                </v-col>
                <v-col align-self="center" jsu class="py-0 pr-0" cols="6">
                  <v-row justify="center">{{transcript2}}</v-row>
                </v-col>
              </v-row>

              <v-divider></v-divider>

              <v-row class="mb-2">
                <v-card tile color="#d0f4f9" width="100%" flat>
                  <v-card-text class="text-center black--text">Daily Class Points</v-card-text>
                </v-card>
              </v-row>

              <v-row>
                <v-col class="py-0 pr-0 font-italic" align-self="center" cols="4">Word</v-col>
                <v-col class="py-0 pr-0 font-italic" align-self="center" cols="8">Definition/Usage</v-col>
              </v-row>
              <v-divider class="my-0"></v-divider>
              <v-row>
                <v-col class="py-0 pr-0" cols="4">
                  <v-text-field v-model="wordSearch1" :loading="loadingwordSearch1" regular placeholder="Word 1" append-icon="search" @click:append="getDefinition1()"></v-text-field>
                </v-col>
                <v-col class="py-0 pr-0" cols="8">
                  <v-tabs v-model="tab1" class="mb-2">
                    <v-tab v-for="item in searchArray1" :key="item">{{item}}</v-tab>
                    <v-tab-item class="mt-2" v-for="item in searchArray1" :key="item">
                      <v-expansion-panels>
                        <v-expansion-panel v-if="item == 'noun'" v-for="noun in nounArray" :key="noun">
                          <v-expansion-panel-header>{{noun.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof noun.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{noun.example}}</span>
                            <br />
                            <span v-if="typeof noun.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in noun.synonyms" :key="synonym">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'verb'" v-for="verb in verbArray" :key="verb">
                          <v-expansion-panel-header>{{verb.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof verb.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{verb.example}}</span>
                            <br />
                            <span v-if="typeof verb.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in verb.synonyms" :key="synonym">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'adjective'" v-for="adjective in adjectiveArray" :key="adjective">
                          <v-expansion-panel-header>{{adjective.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof adjective.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{adjective.example}}</span>
                            <br />
                            <span v-if="typeof adjective.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in adjective.synonyms" :key="synonym">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'pronoun'" v-for="pronoun in pronounArray" :key="pronoun">
                          <v-expansion-panel-header>{{pronoun.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof pronoun.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{pronoun.example}}</span>
                            <br />
                            <span v-if="typeof pronoun.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in pronoun.synonyms" :key="synonym">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'preposition'" v-for="preposition in prepositionArray" :key="preposition">
                          <v-expansion-panel-header>{{preposition.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof preposition.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{preposition.example}}</span>
                            <br />
                            <span v-if="typeof preposition.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in preposition.synonyms" :key="synonym">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'conjunction'" v-for="conjunction in conjunctionArray" :key="conjunction">
                          <v-expansion-panel-header>{{conjunction.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof conjunction.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{conjunction.example}}</span>
                            <br />
                            <span v-if="typeof conjunction.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in conjunction.synonyms" :key="synonym">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'determiner'" v-for="determiner in determinerArray" :key="determiner">
                          <v-expansion-panel-header>{{determiner.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof determiner.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{determiner.example}}</span>
                            <br />
                            <span v-if="typeof determiner.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in determiner.synonyms" :key="synonym">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'exclamation'" v-for="exclamation in exclamationArray" :key="exclamation">
                          <v-expansion-panel-header>{{exclamation.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof exclamation.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{exclamation.example}}</span>
                            <br />
                            <span v-if="typeof exclamation.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in exclamation.synonyms" :key="synonym">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>

                      </v-expansion-panels>
                    </v-tab-item>
                  </v-tabs>

                </v-col>
              </v-row>
              <v-divider class="my-0"></v-divider>
              <v-row>
                <v-col class="py-0 pr-0" cols="4">
                  <v-text-field v-model="wordSearch2" :loading="loadingwordSearch2" regular placeholder="Word 2" append-icon="search" @click:append="getDefinition2()"></v-text-field>
                </v-col>
                <v-col class="py-0 pr-0" cols="8">
                  <v-tabs v-model="tab2" class="mb-2">
                    <v-tab v-for="item in searchArray2" :key="item">{{item}}</v-tab>
                    <v-tab-item class="mt-2" v-for="item in searchArray2" :key="item">
                      <v-expansion-panels>
                        <v-expansion-panel v-if="item == 'noun'" v-for="noun in nounArray2" :key="noun">
                          <v-expansion-panel-header>{{noun.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof noun.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{noun.example}}</span>
                            <br />
                            <span v-if="typeof noun.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in noun.synonyms" :key="synonym2">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'verb'" v-for="verb in verbArray2" :key="verb2">
                          <v-expansion-panel-header>{{verb.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof verb.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{verb.example}}</span>
                            <br />
                            <span v-if="typeof verb.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in verb.synonyms" :key="synonym2">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'adjective'" v-for="adjective in adjectiveArray2" :key="adjective2">
                          <v-expansion-panel-header>{{adjective.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof adjective.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{adjective.example}}</span>
                            <br />
                            <span v-if="typeof adjective.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in adjective.synonyms" :key="synonym2">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'pronoun'" v-for="pronoun in pronounArray2" :key="pronoun2">
                          <v-expansion-panel-header>{{pronoun.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof pronoun.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{pronoun.example}}</span>
                            <br />
                            <span v-if="typeof pronoun.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in pronoun.synonyms" :key="synonym2">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'preposition'" v-for="preposition in prepositionArray2" :key="preposition2">
                          <v-expansion-panel-header>{{preposition.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof preposition.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{preposition.example}}</span>
                            <br />
                            <span v-if="typeof preposition.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in preposition.synonyms" :key="synonym2">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'conjunction'" v-for="conjunction in conjunctionArray2" :key="conjunction2">
                          <v-expansion-panel-header>{{conjunction.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof conjunction.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{conjunction.example}}</span>
                            <br />
                            <span v-if="typeof conjunction.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in conjunction.synonyms" :key="synonym2">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'determiner'" v-for="determiner in determinerArray2" :key="determiner2">
                          <v-expansion-panel-header>{{determiner.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof determiner.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{determiner.example}}</span>
                            <br />
                            <span v-if="typeof determiner.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in determiner.synonyms" :key="synonym2">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel v-if="item == 'exclamation'" v-for="exclamation in exclamationArray2" :key="exclamation2">
                          <v-expansion-panel-header>{{exclamation.definition}}</v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <span v-if="typeof exclamation.example != 'undefined'"><span class="font-weight-medium">Example:</span> {{exclamation.example}}</span>
                            <br />
                            <span v-if="typeof exclamation.synonyms != 'undefined'">
                              <br />
                              <span class="font-weight-medium">Synonyms:</span>
                              <span v-for="synonym in exclamation.synonyms" :key="synonym2">{{synonym}}<br /></span>
                            </span>
                          </v-expansion-panel-content>
                        </v-expansion-panel>

                      </v-expansion-panels>
                    </v-tab-item>
                  </v-tabs>
                </v-col>
              </v-row>

              <v-divider></v-divider>

              <v-row class="mb-2">
                <v-card tile color="#d0f4f9" width="100%" flat>
                  <v-card-text class="text-center black--text">Self Study</v-card-text>
                </v-card>
              </v-row>

              <v-row>
                <v-textarea outlined v-model = "selfStudy"></v-textarea>
              </v-row>

              <v-row>
                <v-spacer></v-spacer>
                <v-btn class="mx-1" color="primary">Send HW</v-btn>
                <v-btn class="mx-1">Close</v-btn>
                <v-btn class="mx-1" color="success" @click = "addEvaluation()">Submit</v-btn>
              </v-row>

            </v-container>


          </v-card>
        </v-col>
      </v-row>
    </v-container>
  </v-app>
</template>

<script>
import vue from 'vue'
import axios from 'axios'
import moment from 'moment'

export default {
  data() {
    return {
        Tutor: [],
        Material: '',
        Curriculum: '',
        Level: '',
        EvaluationError: false,
        Class: [],
        Attendance: '',
        Pronunciation: '',
        Grammar: '',
        Comprehension: '',
        Fluency: '',
        Lesson: '',
        pageNumber: '',
        Constructed1: '',
        Constructed2: '',
        Corrected1: '',
        Corrected2: '',
        encounteredWord1: '',
        encounteredWord2: '',
        Daily1: '',
        Daily2: '',
        selfStudy: '',
      tab1: null,
      tab2: null,
      wordSearch1: '',
      wordSearch2: '',
      wordTranscript1: '',
      wordTranscript2: '',
      transcript1: '',
      transcript2: '',
      loadingwordSearch1: false,
      loadingwordSearch2: false,
      loadingTranscript1: false,
      loadingTranscript2: false,
      searchArray1: [],
      searchArray2: [],
      leftColumn: 12,
      rightColumn: 0,
      rightStyle: 'display:none',
      isMenuShowing: false,
      isSetLevel: true,
      isSetCurriculum: true,
      isSetMaterial: true,
      arrow: 'arrow_left',
      date: new Date().toISOString().substr(0, 10),
      time: new Date().toLocaleString("en-US", {
        timeZone: "Asia/Seoul"
      }).substr(11, 21),

      nounArray: [],
      verbArray: [],
      adjectiveArray: [],
      adverbArray: [],
      pronounArray: [],
      prepositionArray: [],
      conjunctionArray: [],
      determinerArray: [],
      exclamationArray: [],

      nounArray2: [],
      verbArray2: [],
      adjectiveArray2: [],
      adverbArray2: [],
      pronounArray2: [],
      prepositionArray2: [],
      conjunctionArray2: [],
      determinerArray2: [],
      exclamationArray2: [],

      attendance: ['Present', 'Absent'],

      levels: ['Low Beginner', 'Beginner', 'High Beginner', 'Low Intermediate',
      'Intermediate', 'High Intermediate',
      'Pre Advance', 'Advance', 'Post Advance'
    ],

    scores: ['1', '2', '3', '4', '5', '6', '7', '8', '9'],

    curriculums: ['Freetalking', 'Introductory Course', 'Elementary/Intermediate Conversation Course',
    'Regular Conversation', 'New York Live English', 'Grammar Pattern Course', 'Beginner Discussion',
    'Business Course', 'Specialized Job Preparation Course', 'Discussion/Free Talking Course'
  ],

  books: [],

  book_introductory_course: ['Phonics 1', 'Phonics 2', 'Phonics 3', 'Phonics 4', 'Phonics 5', 'Phonics 6',
  'Pattern Practice Junior Basic', 'Pattern Practice Junior Intermediate', 'Pattern Practice Junior Advanced',
  'Conversation Junior Basic', 'Conversation Junior Intermediate', 'Conversation Junior Advanced',
  'Advanced Phonics 1', 'Advanced Phonics 2', 'Advanced Phonics 3'
],

book_elementary_course: ['Milestones 1', 'Milestones 2', 'Milestones 3', 'First Step in Conversation 1',
'First Step in Conversation 2', 'First Step in Conversation 3'
],

book_regular_conversation: ['Conversation 1', 'Conversation 2', 'Conversation 3', 'Conversation 4', 'Conversation 5',
'Interactive English Beginner 1', 'Interactive English Beginner 2', 'Interactive English Beginner 3',
'Interactive English Intermediate 1', 'Interactive English Intermediate 2', 'Interactive English Intermediate 3',
'Interactive English Upper Intermediate 1', 'Interactive English Upper Intermediate 2', 'Interactive English Upper Intermediate 3',
'Interactive English Advanced 1', 'Interactive English Advanced 2', 'Interactive English Advanced 3'
],


book_grammar_pattern: ['Speaking Pattern Drills 1', 'Speaking Pattern Drills 2', 'Speaking Pattern Drills 4', 'Speaking Pattern Drills 5',
'Pattern Practice Adult 1', 'Pattern Practice Adult 2', 'Pattern Practice Adult 3'
],

book_beginner_discussion: ['Easy Topics for Discussion 1', 'Easy Topics for Discussion 2', 'Easy Topics for Discussion 3', 'Easy Topics for Discussion 4',
'Easy Topics for Discussion 5', "Let's Discuss 1", "Let's Discuss 2", "Let's Discuss 3", "Let's Discuss 4", "Let's Discuss 5"
],

book_business_course: ['Business English (Situational Dialogues)', 'Emailing', 'Meeting', 'Negotiation',
'Presentation', 'Business English (Discussion and Analysis)'
],

book_specialize_job_preparation_course: ['Interview', 'Hotel Dialogues', 'Cabin Crew', 'IELTS', 'Medical English',
'Tomato Opic', 'Getting Ready for TOEIC Speaking', 'Opic Advanced', 'Actual TOEIC Speaking'
],

book_discussion_course: ['English Conversation Situation Training 1', 'English Conversation Situation Training 2', 'English Conversation Situation Training 3',
'English Convesation Training Patten Drill 1', 'English Convesation Training Patten Drill 2', 'English Convesation Training Patten Drill 3',
'English Convesation Training Verb Drill 1', 'English Convesation Training Verb Drill 2', 'English Convesation Training Verb Drill 3',
'BIZ E-MAIL ENGLISH', 'BIZ TELEPHONE ENGLISH', 'BIZ PRESENTATION ENGLISH', 'BIZ MEETING DISCUSSION ENGLISH'
],

}
},

mounted(){


const classId = this.$route.params.classid



const form = new FormData();

form.append('classId', classId)

axios.post('Tutor/getRegularStudent', form).then(res => {


  console.log(res.data, 'data')


  if(res.data.evaluation){
    const evaluation  = JSON.parse(res.data.evaluation.evaluation)


    if(res.data.evaluation.type === 'regularclass'){




      this.Attendance = evaluation.Attendance
      this.Pronunciation = evaluation.Pronunciation
      this.Grammar = evaluation.Grammar
      this.Comprehension = evaluation.Comprehension
      this.Fluency = evaluation.Fluency
      this.Lesson = evaluation.Lesson
      this.pageNumber = evaluation.pageNumber
      this.Constructed1 = evaluation.Constructed1
      this.Constructed2 = evaluation.Constructed2
      this.Corrected1 = evaluation.Corrected1
      this.Corrected2 = evaluation.Corrected2
      this.wordSearch1 = evaluation.wordSearch1
      this.wordSearch2 = evaluation.wordSearch2
      this.wordTranscript1 = evaluation.wordTranscript1
      this.wordTranscript2 = evaluation.wordTranscript2
      this.selfStudy = evaluation.selfStudy

      this.date = evaluation.date

      this.Level = res.data.class['schedule']['level']





      this.Curriculum = res.data.class['schedule']['curriculum']

        this.onChangeCurriculum(this.Curriculum)

            this.Material  = res.data.class['schedule']['bookMaterial']










}


if(res.data.evaluation.type === 'leveltest'){

  this.Level = evaluation.Level





  this.Curriculum = evaluation.Curriculum

    this.onChangeCurriculum(evaluation.Curriculum)

        this.Material  = evaluation.Material

}

    console.log(evaluation, 'eval')
  }




  this.$set(this.$data, 'Tutor', res.data.tutor)
  this.$set(this.$data, 'Class', res.data.class)



  this.showMenu()



  console.log(res.data, 'data')

})
  },






methods: {
  showMenu() {

    if (!this.isMenuShowing) {
      this.leftColumn = 5
      this.rightColumn = 7
      this.rightStyle = ''
      this.isMenuShowing = true
      this.arrow = 'arrow_right'
    } else {
      this.leftColumn = 12
      this.rightColumn = 0
      this.rightStyle = 'display:none'
      this.isMenuShowing = false
      this.arrow = 'arrow_left'
    }
  },


  onChangeCurriculum(event) {
    if (event == 'Freetalking') {
      vue.set(this.$data, 'books', [])
    } else if (event == 'Introductory Course') {
      vue.set(this.$data, 'books', this.$data.book_introductory_course)
    } else if (event == 'Elementary/Intermediate Conversation Course') {
      vue.set(this.$data, 'books', this.$data.book_elementary_course)
    } else if (event == 'Regular Conversation') {
      vue.set(this.$data, 'books', this.$data.book_regular_conversation)
    } else if (event == 'New York Live English') {
      vue.set(this.$data, 'books', [])
    } else if (event == 'Grammar Pattern Course') {
      vue.set(this.$data, 'books', this.$data.book_grammar_pattern)
    } else if (event == 'Beginner Discussion') {
      vue.set(this.$data, 'books', this.$data.book_beginner_discussion)
    } else if (event == 'Business Course') {
      vue.set(this.$data, 'books', this.$data.book_business_course)
    } else if (event == 'Specialized Job Preparation Course') {
      vue.set(this.$data, 'books', this.$data.book_specialize_job_preparation_course)
    } else if (event == 'Discussion/Free Talking Course') {
      vue.set(this.$data, 'books', this.$data.book_discussion_course)
    }
  },

  getDefinition1() {
    const proxy = "https://cors-anywhere.herokuapp.com/"
    const URL = 'https://googledictionaryapi.eu-gb.mybluemix.net/?define=' + this.wordSearch1 + '&lang=en';
    console.log(proxy + URL)
    this.loadingwordSearch1 = true
    axios.get(proxy + URL).then((response) => {
      this.loadingwordSearch1 = false

      this.searchArray1 = []
      this.nounArray = []
      this.verbArray = []
      this.adjectiveArray = []
      this.adverbArray = []
      this.pronounArray = []
      this.prepositionArray = []
      this.conjunctionArray = []
      this.determinerArray = []
      this.exclamationArray = []


      for (let i = 0; i < response.data.length; i++) {

        for (let key in response.data[i]) {

          if (response.data[i].hasOwnProperty(key) && key == 'meaning') {

            for (let key in response.data[i]['meaning']) {

              if (response.data[i]['meaning'].hasOwnProperty(key) && this.searchArray1.indexOf(key) == -1) {

                if (key.indexOf('verb') != -1 && key != 'adverb') {
                  this.searchArray1.push('verb')
                } else {
                  this.searchArray1.push(key)
                }

                for (let j = 0; j < this.searchArray1.length; j++) {

                  if (key == this.searchArray1[j] || key.indexOf('verb') != 1) {

                    for (let k = 0; k < response.data[i]['meaning'][key].length; k++) {

                      if (key.indexOf('verb') != -1 && key != 'adverb' && this.verbArray.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.verbArray.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'noun' && this.nounArray.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.nounArray.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'pronoun' && this.pronounArray.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.pronounArray.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'adjective' && this.adjectiveArray.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.adjectiveArray.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'adverb' && this.adverbArray.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.adverbArray.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'preposition' && this.prepositionArray.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.prepositionArray.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'conjunction' && this.conjunctionArray.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.conjunctionArray.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'determiner' && this.determinerArray.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.determinerArray.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'exclamation' && this.exclamationArray.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.exclamationArray.push(response.data[i]['meaning'][key][k])
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    })
  },

  getDefinition2() {
    const proxy = "https://cors-anywhere.herokuapp.com/"
    const URL = 'https://googledictionaryapi.eu-gb.mybluemix.net/?define=' + this.wordSearch2 + '&lang=en';
    console.log(proxy + URL)
    this.loadingwordSearch2 = true
    axios.get(proxy + URL).then((response) => {
      this.loadingwordSearch2 = false

      this.searchArray2 = []
      this.nounArray2 = []
      this.verbArray2 = []
      this.adjectiveArray2 = []
      this.adverbArray2 = []
      this.pronounArray2 = []
      this.prepositionArray2 = []
      this.conjunctionArray2 = []
      this.determinerArray2 = []
      this.exclamationArray2 = []


      for (let i = 0; i < response.data.length; i++) {

        for (let key in response.data[i]) {

          if (response.data[i].hasOwnProperty(key) && key == 'meaning') {

            for (let key in response.data[i]['meaning']) {

              if (response.data[i]['meaning'].hasOwnProperty(key) && this.searchArray2.indexOf(key) == -1) {

                if (key.indexOf('verb') != -1 && key != 'adverb') {
                  this.searchArray2.push('verb')
                } else {
                  this.searchArray2.push(key)
                }

                for (let j = 0; j < this.searchArray2.length; j++) {

                  if (key == this.searchArray2[j] || key.indexOf('verb') != 1) {

                    for (let k = 0; k < response.data[i]['meaning'][key].length; k++) {


                      if (key.indexOf('verb') != -1 && key != 'adverb' && this.verbArray2.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.verbArray2.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'noun' && this.nounArray2.indexOf(response.data[i]['meaning'][key][k]) == -1 && Object.keys(response.data[i]['meaning'][key][k]).length !== 0) {
                        this.nounArray2.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'pronoun' && this.pronounArray2.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.pronounArray2.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'adjective' && this.adjectiveArray2.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.adjectiveArray2.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'adverb' && this.adverbArray2.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.adverbArray2.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'preposition' && this.prepositionArray2.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.prepositionArray2.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'conjunction' && this.conjunctionArray2.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.conjunctionArray2.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'determiner' && this.determinerArray2.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.determinerArray2.push(response.data[i]['meaning'][key][k])
                      } else if (key == 'exclamation' && this.exclamationArray2.indexOf(response.data[i]['meaning'][key][k]) == -1) {
                        this.exclamationArray2.push(response.data[i]['meaning'][key][k])
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

    })
  },

  getTranscript1() {
    const proxy = "https://cors-anywhere.herokuapp.com/"
    const URL = 'https://googledictionaryapi.eu-gb.mybluemix.net/?define=' + this.wordTranscript1 + '&lang=en';
    console.log(proxy + URL)
    this.loadingTranscript1 = true
    axios.get(proxy + URL).then((response) => {
      this.loadingTranscript1 = false
      this.transcript1 = response.data[0].phonetic
    })

  },

  getTranscript2() {
    const proxy = "https://cors-anywhere.herokuapp.com/"
    const URL = 'https://googledictionaryapi.eu-gb.mybluemix.net/?define=' + this.wordTranscript2 + '&lang=en';
    console.log(proxy + URL)
    this.loadingTranscript2 = true
    axios.get(proxy + URL).then((response) => {
      this.loadingTranscript2 = false
      this.transcript2 = response.data[0].phonetic
    })

  },

  getEndContract(){


  let class_end_schedule = this.Class['schedule']['class_end'].split(",")

  let end_schedule =  class_end_schedule[class_end_schedule.length-1]

  return end_schedule.split(" ")[0]




},

getApplicableDays(){

  return this.Class['schedule']['applicable_days'].substr(0,this.Class['schedule']['applicable_days'].length -1 ).substr(1)
},

getHour(){

  return moment({hour: this.Class['schedule']['hour'], minute:this.Class['schedule']['minute']}).format('HH:mm:ss')


},

UpdateLevel(){

  if(this.isSetLevel === true){

    this.isSetLevel = false
  }
},

 async SaveLevel(){


      const data = prompt('Enter classid for confirmation')


      if(data === this.Class['schedule']['classid'] && this.Level){

        const classid = this.Class['schedule']['classid']
        const form = new FormData()
        form.append('classid', classid)
        form.append('Level', this.Level)
        axios.post('Tutor/saveLevel', form).then(res => {

          console.log(res.data)
        })
      }

},


UpdateCurriculum(){

  if(this.isSetCurriculum === true){

    this.isSetCurriculum = false
  }
},

 async SaveCurriculum(){


   const data = prompt('Enter classid for confirmation')


   if(data === this.Class['schedule']['classid'] && this.Curriculum && this.Material){

     const classid = this.Class['schedule']['classid']
     const form = new FormData()
     form.append('classid', classid)
     form.append('Curriculum', this.Curriculum)
     form.append('Material', this.Material)

     axios.post('Tutor/SaveCurriculum', form).then(res => {

       console.log(res.data)
     })
   }

},




addEvaluation(){


const studentname = this.Class['schedule']['name']
const tutorname = this.Tutor['mega_name']
const tutoridx = this.Tutor['idx']
const classid =  this.Class['schedule']['classid']
const phone_number = this.Class['schedule']['phone_number']



const Lesson = this.Lesson

const pageNumber = this.pageNumber
const Attendance = this.Attendance


const selfStudy = this.selfStudy

const Evaluation = {Lesson:Lesson, pageNumber: pageNumber, Attendance: Attendance, selfStudy: selfStudy , Pronunciation: this.Pronunciation, Grammar: this.Grammar, Comprehension: this.Comprehension, Fluency: this.Fluency,  Constructed1: this.Constructed1, Constructed2: this.Constructed2, Corrected1: this.Corrected1, Corrected2: this.Corrected2, wordTranscript1: this.wordTranscript1, wordTranscript2: this.wordTranscript2,wordSearch1: this.wordSearch1, wordSearch2: this.wordSearch2, date: moment().format('YYYY-MM-DD'), tutorName: tutorname, tutorIdx: tutoridx, classid: classid}


const checkObj =  Object.values(Evaluation).some(data => (data === null || data === ''))


if(checkObj === true || !this.Level || !this.Curriculum || !this.Material || !studentname || !classid ){

  this.EvaluationError = true
  this.$vuetify.goTo(0)
}

else{
const form = new FormData()
form.append('evaluation', JSON.stringify(Evaluation))
form.append('studentname', studentname)
form.append('classid', classid)
form.append('phone_number', phone_number)


axios.post('Evaluation/addEvaluation', form).then(res => {

  if(res.data.error === false){

    window.close()
  }

  console.log(res.data, 'data')
}).catch(err => {

  console.log(err, 'err')
})

}



}








}
}
</script>

<style lang="css">
</style>
